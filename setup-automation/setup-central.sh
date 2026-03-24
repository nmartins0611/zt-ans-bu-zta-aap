#!/bin/bash
set -euo pipefail
systemctl stop firewalld
setenforce 0

echo "Setup the AH Token for ansible"
###############################################################################
# Setup AH
###############################################################################

if [ -z "$AH_TOKEN" ]; then
    echo "Error: AH_TOKEN environment variable is not set"
    echo "Usage: AH_TOKEN='your-token-here' $0"
    exit 1
fi

# Create ~/.ansible.cfg with AH_TOKEN substituted
tee ~/.ansible.cfg > /dev/null <<EOF
[defaults]
[galaxy]
server_list = automation_hub, validated, galaxy
[galaxy_server.automation_hub]
url = https://console.redhat.com/api/automation-hub/content/published/
auth_url = https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token
token=$AH_TOKEN
[galaxy_server.validated]
url = https://console.redhat.com/api/automation-hub/content/validated/
auth_url = https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token
token=$AH_TOKEN
[galaxy_server.galaxy]
url=https://galaxy.ansible.com/
#token=""
[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
pipelining = True
EOF


echo "Setup the Satellite links"

###############################################################################
# Helpers
###############################################################################

retry() {
    local max_attempts=3
    local delay=5
    local desc="$1"
    shift
    for ((i = 1; i <= max_attempts; i++)); do
        echo "Attempt $i/$max_attempts: $desc"
        if "$@"; then
            return 0
        fi
        if [ $i -lt $max_attempts ]; then
            echo "  Failed. Retrying in ${delay}s..."
            sleep $delay
        fi
    done
    echo "FATAL: Failed after $max_attempts attempts: $desc"
    exit 1
}

run_if_needed() {
    local desc="$1"
    shift
    local check=()
    while [[ "$1" != "--" ]]; do
        check+=("$1"); shift
    done
    shift
    if "${check[@]}" &>/dev/null; then
        echo "SKIP (already done): $desc"
    else
        retry "$desc" "$@"
    fi
}

ensure_hosts_entry() {
    local ip="$1"
    local names="$2"
    if grep -q "^${ip} " /etc/hosts 2>/dev/null; then
        echo "SKIP: /etc/hosts already has entry for ${ip}"
    else
        echo "${ip} ${names}" >> /etc/hosts
    fi
}

ensure_nmcli_connection() {
    local con_name="$1"
    shift
    if nmcli connection show "$con_name" &>/dev/null; then
        echo "SKIP: nmcli connection '${con_name}' already exists"
    else
        nmcli connection add "$@"
    fi
}

###############################################################################
# 1. Validate required variables
###############################################################################

for var in SATELLITE_URL SATELLITE_ORG SATELLITE_ACTIVATIONKEY; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is not set"
        exit 1
    fi
done

###############################################################################
# 2. Disable tmpfiles service
###############################################################################

# if systemctl is-active --quiet systemd-tmpfiles-setup.service; then
#     systemctl stop systemd-tmpfiles-setup.service
# else
#     echo "SKIP: systemd-tmpfiles-setup already stopped"
# fi

# if systemctl is-enabled --quiet systemd-tmpfiles-setup.service 2>/dev/null; then
#     systemctl disable systemd-tmpfiles-setup.service
# else
#     echo "SKIP: systemd-tmpfiles-setup already disabled"
# fi

###############################################################################
# 3. Clean repos & subscriptions (only if not already registered)
###############################################################################

if subscription-manager identity &>/dev/null; then
    echo "SKIP: Already registered with Satellite – skipping clean/unregister"
else
    echo "Cleaning existing repos and subscriptions..."
    dnf clean all || true
    rm -f /etc/yum.repos.d/redhat-rhui*.repo
    sed -i 's/enabled=1/enabled=0/' /etc/dnf/plugins/amazon-id.conf 2>/dev/null || true
    subscription-manager unregister 2>/dev/null || true
    subscription-manager remove --all 2>/dev/null || true
    subscription-manager clean

    OLD_KATELLO=$(rpm -qa | grep katello-ca-consumer || true)
    if [ -n "$OLD_KATELLO" ]; then
        rpm -e "$OLD_KATELLO" 2>/dev/null || true
    fi
fi

###############################################################################
# 4. Register with Satellite
###############################################################################

CA_CERT="/etc/pki/ca-trust/source/anchors/${SATELLITE_URL}.ca.crt"

run_if_needed "Download Katello CA cert" \
    test -f "${CA_CERT}" \
    -- \
    curl -fsSkL \
        "https://${SATELLITE_URL}/pub/katello-server-ca.crt" \
        -o "${CA_CERT}"

retry "Update CA trust" \
    update-ca-trust extract

run_if_needed "Install Katello consumer RPM" \
    rpm -q katello-ca-consumer \
    -- \
    rpm -Uhv --force "https://${SATELLITE_URL}/pub/katello-ca-consumer-latest.noarch.rpm"

run_if_needed "Register with Satellite" \
    subscription-manager identity \
    -- \
    subscription-manager register \
        --org="${SATELLITE_ORG}" \
        --activationkey="${SATELLITE_ACTIVATIONKEY}"

retry "Refresh subscription" \
    subscription-manager refresh

###############################################################################
# 5. Install packages
###############################################################################

run_if_needed "Install base packages" \
    rpm -q dnf-utils git nano \
    -- \
    dnf install -y dnf-utils git nano

run_if_needed "Install system packages" \
    rpm -q python3-libsemanage ansible-core python-requests ipa-client sssd oddjob-mkhomedir \
    -- \
    dnf install -y python3-libsemanage git ansible-core python-requests \
                   ipa-client sssd oddjob-mkhomedir

###############################################################################
# 6. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control"
ensure_hosts_entry "192.168.1.11" "central.zta.lab keycloak.zta.lab opa.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.13" "wazuh.zta.lab wazuh"
ensure_hosts_entry "192.168.1.14" "node01.zta.lab node01"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"

###############################################################################
# 7. Network configuration (idempotent)
###############################################################################

ensure_nmcli_connection "enp2s0" \
    type ethernet con-name enp2s0 ifname enp2s0 \
    ipv4.addresses 192.168.1.11/24 \
    ipv4.method manual \
    connection.autoconnect yes

nmcli connection up enp2s0 || true

###############################################################################
# 8. Clone workshop repo (idempotent)
###############################################################################

# if [ -d /tmp/zta-workshop-aap ]; then
#     echo "SKIP: /tmp/zta-workshop-aap already exists"
# else
#     retry "Clone ZTA workshop repo" \
#         git clone https://github.com/nmartins0611/zta-workshop-aap.git /tmp/zta-workshop-aap
        
# fi
if [ -d /tmp/zta-workshop-aap ]; then
    echo "SKIP: /tmp/zta-workshop-aap already exists"
else
    retry "Clone ZTA workshop repo (idm_dev branch)" \
        git clone -b idm_dev https://github.com/nmartins0611/zta-workshop-aap.git /tmp/zta-workshop-aap
fi

###############################################################################
# 9. Create supporting directories and files
###############################################################################

mkdir -p /tmp/group_vars

tee /tmp/group_vars/all.yml << 'EOF'
---
# ── Lab Identity ─────────────────────────────────────────────────────
idm_hostname: central.zta.lab
idm_domain: zta.lab
idm_realm: "{{ idm_domain | upper }}"
idm_admin_password: ansible123!
idm_dm_password: ansible123!

# ── OPA (Open Policy Agent) — runs on central alongside IdM ─────────
opa_url: "http://central.zta.lab:8181"
opa_container_name: opa
opa_policy_dir: /opt/opa/policies

# ── HashiCorp Vault (own VM) ────────────────────────────────────────
vault_addr: "https://vault.zta.lab:8200"
vault_skip_verify: true

# ── Netbox / CMDB (own VM) ──────────────────────────────────────────
netbox_url: "http://netbox.zta.lab:8000"
netbox_token: "{{ lookup('env', 'NETBOX_TOKEN') }}"

# ── Gitea / Git Server (own container) ──────────────────────────────
gitea_url: "http://gitea.zta.lab:3000"
gitea_org: zta-workshop
gitea_repo: zta-app
gitea_webhook_secret: "{{ lookup('env', 'GITEA_WEBHOOK_SECRET') | default('zta-webhook-secret', true) }}"

# ── Wazuh / SIEM (own VM) ──────────────────────────────────────────
wazuh_url: "https://wazuh.zta.lab"
wazuh_api_url: "https://wazuh.zta.lab:55000"
wazuh_api_user: wazuh
wazuh_api_password: "{{ lookup('env', 'WAZUH_API_PASSWORD') | default('wazuh', true) }}"
wazuh_manager_host: wazuh.zta.lab

# ── AAP Controller (own VM) ─────────────────────────────────────────
aap_controller_url: "https://control.zta.lab"
aap_validate_certs: false

# ── Cisco Catalyst 8000v (own VM) ───────────────────────────────────
cisco_switch_host: switch01.zta.lab

# ── Database / PostgreSQL (own VM) ──────────────────────────────────
db_host: db.zta.lab
db_port: 5432
db_name: ztaapp
db_admin_user: postgres
db_admin_password: "{{ lookup('env', 'DB_ADMIN_PASSWORD') | default('postgres123!', true) }}"

# ── Application Server (own VM) ─────────────────────────────────────
app_host: app.zta.lab
app_port: 8080
app_deploy_dir: /opt/ztaapp

# ── IdM Teams (organisational units) ────────────────────────────────
idm_teams:
  - name: team-infrastructure
    description: Infrastructure & Platform Engineering
  - name: team-devops
    description: DevOps & CI/CD
  - name: team-security
    description: Security Operations & Compliance
  - name: team-applications
    description: Application Development

# ── IdM Functional Groups (used in OPA policies for RBAC) ──────────
idm_groups:
  - name: zta-admins
    description: ZTA Lab Administrators — full access
  - name: patch-admins
    description: Server patching operators
  - name: network-admins
    description: Network configuration operators
  - name: app-deployers
    description: Application deployment operators
  - name: security-ops
    description: Security operations — Wazuh, audit, compliance
  - name: db-admins
    description: Database administration
  - name: change-approvers
    description: Can approve maintenance windows and change requests

# ── IdM Users ──────────────────────────────────────────────────────
idm_workshop_users:
  - uid: ztauser
    first: ZTA
    last: User
    title: Workshop Admin
    groups: [zta-admins, patch-admins, app-deployers, team-infrastructure]
  - uid: netadmin
    first: Network
    last: Admin
    title: Workshop Network Admin
    groups: [zta-admins, network-admins, team-infrastructure]
  - uid: appdev
    first: App
    last: Developer
    title: Workshop App Developer
    groups: [app-deployers, team-applications]
  - uid: neteng
    first: Network
    last: Engineer
    title: Workshop Network Engineer (no groups — will be denied)
    groups: []
  - uid: jsmith
    first: James
    last: Smith
    title: Infrastructure Team Lead
    groups: [zta-admins, patch-admins, change-approvers, team-infrastructure]
  - uid: rwilson
    first: Robert
    last: Wilson
    title: Senior Systems Administrator
    groups: [patch-admins, team-infrastructure]
  - uid: nobrien
    first: Nora
    last: O'Brien
    title: Database Administrator
    groups: [db-admins, patch-admins, team-infrastructure]
  - uid: djohnson
    first: David
    last: Johnson
    title: Network Architect
    groups: [network-admins, change-approvers, team-infrastructure]
  - uid: agarcia
    first: Ana
    last: Garcia
    title: Network Engineer
    groups: [network-admins, team-infrastructure]
  - uid: lkim
    first: Lisa
    last: Kim
    title: DevOps Lead
    groups: [zta-admins, app-deployers, change-approvers, team-devops]
  - uid: mchen
    first: Michael
    last: Chen
    title: DevOps Engineer
    groups: [app-deployers, patch-admins, team-devops]
  - uid: ksato
    first: Kenji
    last: Sato
    title: Platform Engineer
    groups: [app-deployers, patch-admins, team-devops]
  - uid: mrodriguez
    first: Maria
    last: Rodriguez
    title: Security Lead
    groups: [zta-admins, security-ops, change-approvers, team-security]
  - uid: spatel
    first: Sarah
    last: Patel
    title: Security Analyst
    groups: [security-ops, team-security]
  - uid: twright
    first: Tom
    last: Wright
    title: Junior Developer
    groups: [app-deployers, team-applications]
  - uid: ebell
    first: Emma
    last: Bell
    title: Senior Developer
    groups: [app-deployers, team-applications]
  - uid: cmorales
    first: Carlos
    last: Morales
    title: QA Engineer
    groups: [team-applications]
  - uid: pryan
    first: Patricia
    last: Ryan
    title: Release Manager
    groups: [app-deployers, change-approvers, team-applications]
  - uid: fnguyen
    first: Felix
    last: Nguyen
    title: SOC Analyst
    groups: [security-ops, team-security]

# ── Vault Paths ─────────────────────────────────────────────────────
vault_db_secrets_path: database
vault_kv_secrets_path: secret
vault_db_role_name: ztaapp-short-lived
vault_db_max_ttl: 1h
vault_db_default_ttl: 5m

# ── Network Segmentation ────────────────────────────────────────────
vlans:
  app_tier:
    id: 20
    name: APP-TIER
    network: 10.20.0.0/24
  data_tier:
    id: 30
    name: DATA-TIER
    network: 10.30.0.0/24
  management:
    id: 10
    name: MGMT
    network: 10.10.0.0/24
EOF

tee /tmp/requirements.yml << 'EOF'
---
collections:
  - name: cisco.ios
  - name: ansible.netcommon
  - name: community.postgresql
  - name: community.general
  - name: redhat.rhel_idm
  - name: containers.podman
EOF

tee /tmp/inventory << 'EOF'
[zta_services]
central ansible_host=central.zta.lab

[vault_servers]
vault ansible_host=vault.zta.lab

[netbox_servers]
netbox ansible_host=netbox.zta.lab

[wazuh_servers]
wazuh ansible_host=wazuh.zta.lab

[automation]
control ansible_host=control.zta.lab

[app_servers]
app ansible_host=node01.zta.lab

[db_servers]
db ansible_host=node01.zta.lab

[idm_clients:children]
vault_servers
netbox_servers
wazuh_servers
app_servers
db_servers

[all:vars]
ansible_user=rhel
ansible_password=ansible123!
ansible_become_password=ansible123!
ansible_python_interpreter=/usr/bin/python3
EOF

###############################################################################
# 10. Install Ansible collections
###############################################################################
echo "Install Collections for Ansible Setup"

retry "Install Ansible collections" \
    ansible-galaxy collection install -r /tmp/requirements.yml

###############################################################################
# 11. ZTA verification playbook + integrate
###############################################################################

tee /tmp/zta-setup.yml << 'PLAYBOOK'
---
- name: Verify ZTA Lab services on central.zta.lab
  hosts: localhost
  become: true
  gather_facts: true

  tasks:

    - name: Start IdM services
      ansible.builtin.command:
        cmd: ipactl start
      register: _ipactl
      changed_when: "'already running' not in _ipactl.stdout | default('')"
      failed_when: _ipactl.rc != 0

    - name: Check hostname
      ansible.builtin.command:
        cmd: hostname -f
      register: hostname_check
      changed_when: false

    - name: Check IP address
      ansible.builtin.debug:
        msg: "IP: {{ ansible_default_ipv4.address }} | Hostname: {{ hostname_check.stdout }}"

    - name: Verify IdM services
      ansible.builtin.command:
        cmd: ipactl status
      register: ipa_status
      changed_when: false
      failed_when: false

    - name: Display IdM status
      ansible.builtin.debug:
        var: ipa_status.stdout_lines

    - name: Flag any stopped IdM services
      ansible.builtin.assert:
        that:
          - "'STOPPED' not in ipa_status.stdout"
          - ipa_status.rc == 0
        fail_msg: "One or more IdM services are not running"
        success_msg: "All IdM services are running"

    - name: Check Keycloak container
      ansible.builtin.command:
        cmd: podman ps --filter name=keycloak --format "{{ '{{' }}.Status{{ '}}' }}"
      register: keycloak_status
      changed_when: false
      failed_when: false

    - name: Start Keycloak if not running
      ansible.builtin.systemd:
        name: container-keycloak
        state: started
      when: "'Up' not in keycloak_status.stdout"

    - name: Verify Keycloak HTTP responds
      ansible.builtin.uri:
        url: "http://localhost:{{ keycloak_http_port | default(8180) }}"
        method: GET
        status_code: 200
        validate_certs: false
      register: keycloak_health
      retries: 5
      delay: 10
      until: keycloak_health.status == 200

    - name: Check OPA container
      ansible.builtin.command:
        cmd: podman ps --filter name=opa --format "{{ '{{' }}.Status{{ '}}' }}"
      register: opa_status
      changed_when: false
      failed_when: false

    - name: Start OPA if not running
      ansible.builtin.systemd:
        name: container-opa
        state: started
      when: "'Up' not in opa_status.stdout"

    - name: Verify OPA health endpoint
      ansible.builtin.uri:
        url: "http://localhost:{{ opa_http_port | default(8181) }}/health"
        method: GET
        status_code: 200
      register: opa_health
      retries: 5
      delay: 5
      until: opa_health.status == 200

    - name: Verify OPA policies are loaded
      ansible.builtin.uri:
        url: "http://localhost:{{ opa_http_port | default(8181) }}/v1/policies"
        method: GET
        status_code: 200
        return_content: true
      register: opa_policies

    - name: Verify DNS resolution
      ansible.builtin.command:
        cmd: "dig +short {{ item }} @127.0.0.1"
      register: dns_checks
      changed_when: false
      failed_when: dns_checks.stdout | length == 0
      loop:
        - central.zta.lab
        - keycloak.zta.lab
        - opa.zta.lab

    - name: Verify Kerberos
      ansible.builtin.shell:
        cmd: echo '{{ idm_admin_password | default("ansible123!") }}' | kinit admin && klist
      register: krb_check
      changed_when: false
      no_log: true

    - name: Verification summary
      ansible.builtin.debug:
        msg:
          - "============================================="
          - "  ZTA Lab - Verification Results"
          - "============================================="
          - "  Hostname:   {{ hostname_check.stdout }}"
          - "  IP Address: {{ ansible_default_ipv4.address }}"
          - ""
          - "  IdM:        {{ 'OK - All services running' if ipa_status.rc == 0 else 'FAILED' }}"
          - "  Keycloak:   {{ 'OK - HTTP 200' if keycloak_health.status == 200 else 'FAILED' }}"
          - "  OPA:        {{ 'OK - Healthy, ' + ((opa_policies.json.result | default([])) | length | string) + ' policies loaded' if opa_health.status == 200 else 'FAILED' }}"
          - "  DNS:        OK - all records resolve"
          - "  Kerberos:   OK - admin ticket obtained"
          - "============================================="
PLAYBOOK
ansible-playbook -i /tmp/inventory /tmp/zta-setup.yml
##############################################################################
# 12. Run integration playbook and IDM DNS
###############################################################################
#ansible-playbook -i /tmp/inventory /tmp/zta-workshop-aap/integrate.yml
#ansible-playbook -i /tmp/zta-workshop-aap/inventory/hosts.ini tmp/zta-workshop-aap/setup/configure-dns.yml
###############################################################################
# 13. IPA rewrite config (idempotent) — must run after integrate.yml
###############################################################################

IPA_REWRITE="/etc/httpd/conf.d/ipa-rewrite.conf"
if grep -q "RequestHeader set Host central.zta.lab" "$IPA_REWRITE" 2>/dev/null; then
    echo "SKIP: ipa-rewrite.conf already configured"
else
    tee "$IPA_REWRITE" << 'IPA'
# VERSION 7 - DO NOT REMOVE THIS LINE
RequestHeader set Host central.zta.lab
RequestHeader set Referer https://central.zta.lab/ipa/ui/
RewriteEngine on
RewriteRule ^/ipa/ui/js/freeipa/plugins.js$    /ipa/wsgi/plugins.py [PT]
RewriteCond %{HTTP_HOST}    ^ipa-ca.example.local$ [NC]
RewriteCond %{REQUEST_URI}  !^/ipa/crl
RewriteCond %{REQUEST_URI}  !^/(ca|kra|pki|acme)
IPA
    systemctl reload httpd
fi

rm -rf ~/.ansible.cfg

echo "✓ central setup complete"
