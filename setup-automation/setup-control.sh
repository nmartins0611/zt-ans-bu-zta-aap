#!/bin/bash
set -euo pipefail

echo "Starting Control node setup..."
export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False
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
    while [[ $# -gt 0 && "${1}" != "--" ]]; do
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
# 1. Validate required environment variables
###############################################################################

for var in TMM_ORG TMM_ID; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var environment variable is not set"
        echo "Usage: TMM_ORG='...' TMM_ID='...' $0"
        exit 1
    fi
done

###############################################################################
# 2. SELinux — set permissive (idempotent)
###############################################################################

CURRENT_MODE=$(getenforce)
if [ "${CURRENT_MODE}" = "Permissive" ] || [ "${CURRENT_MODE}" = "Disabled" ]; then
    echo "SKIP: SELinux already in ${CURRENT_MODE} mode"
else
    setenforce 0
    echo "SELinux set to Permissive"
fi

###############################################################################
# 3. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control aap.zta.lab"
ensure_hosts_entry "192.168.1.11" "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"
ensure_hosts_entry "192.168.1.13" "wazuh.zta.lab wazuh"

###############################################################################
# 4. Network configuration (idempotent)
###############################################################################

echo "Configuring network interface..."
ensure_nmcli_connection "eth1" \
    type ethernet con-name eth1 ifname eth1 \
    ipv4.addresses 192.168.1.10/24 \
    ipv4.method manual \
    ipv4.dns 192.168.1.11 \
    ipv4.dns-search zta.lab \
    connection.autoconnect yes

nmcli connection up eth1 || true

###############################################################################
# 5. Register with subscription manager (idempotent)
###############################################################################

if subscription-manager identity &>/dev/null; then
    echo "SKIP: Already registered – skipping registration"
else
    echo "Cleaning existing repos and subscriptions..."
    dnf clean all || true
    rm -f /etc/yum.repos.d/redhat-rhui*.repo
    sed -i 's/enabled=1/enabled=0/' /etc/dnf/plugins/amazon-id.conf 2>/dev/null || true
    subscription-manager unregister 2>/dev/null || true
    subscription-manager remove --all 2>/dev/null || true
    subscription-manager clean

    echo "Registering with subscription manager..."
    if subscription-manager register --org="$TMM_ORG" --activationkey="$TMM_ID" --force; then
        echo "System registered successfully!"
    else
        echo "Registration failed. Please check your credentials and network connection."
        exit 1
    fi
fi

###############################################################################
# 6. Enable subscription-manager repo management (idempotent)
###############################################################################

CURRENT_MANAGE_REPOS=$(subscription-manager config --list | grep -oP 'manage_repos\s*=\s*\[\K[^\]]+' || echo "unknown")
if [ "$CURRENT_MANAGE_REPOS" = "1" ]; then
    echo "SKIP: manage_repos already enabled"
else
    subscription-manager config --rhsm.manage_repos=1
    subscription-manager refresh
fi

###############################################################################
# 5. Setup Ansible configuration with AH Token
###############################################################################

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


###############################################################################
# 7. Install packages
###############################################################################

run_if_needed "Install base packages" \
    rpm -q dnf-utils \
    -- \
    dnf install -y dnf-utils git nano

run_if_needed "Install IPA client packages" \
    rpm -q ipa-client \
    -- \
    dnf install -y ipa-client sssd oddjob-mkhomedir

run_if_needed "Install Python3 libraries" \
    rpm -q python3-libsemanage \
    -- \
    dnf install -y python3-libsemanage

###############################################################################
# 10. Clone workshop repo (idempotent)
###############################################################################

if [ -d /tmp/zta-workshop-aap ]; then
    echo "SKIP: /tmp/zta-workshop-aap already exists"
else
    retry "Clone ZTA workshop repo (zta-container branch)" \
        git clone -b zta-container https://github.com/nmartins0611/zta-workshop-aap.git /tmp/zta-workshop-aap
fi

###############################################################################
# 11. Install Ansible collections
###############################################################################
tee /tmp/requirements.yml > /dev/null <<EOF
---
collections:
  - name: cisco.ios
  - name: arista.eos
  - name: ansible.netcommon
  - name: community.postgresql
  - name: community.general
  - name: redhat.rhel_idm
  - name: netbox.netbox
  - name: containers.podman
  - name: ansible.controller
  - name: ansible.posix

EOF


run_if_needed "Install community.general collection" \
    bash -c 'ansible-galaxy collection list | grep -q "ansible.controller"' \
    -- \
    ansible-galaxy install -r /tmp/requirements.yml

cp /tmp/zta-workshop-aap/ansible.cfg /etc/ansible/
###############################################################################
# 15. Run Ansible playbooks
###############################################################################
PLAYBOOK_DIR="/tmp/zta-workshop-aap"
cd "${PLAYBOOK_DIR}" || { echo "ERROR: Cannot cd to ${PLAYBOOK_DIR}"; exit 1; }
ansible-playbook -i inventory/hosts.ini setup/configure-aap-credentials.yml
##ansible-playbook -i inventory/hosts.ini setup/configure-aap-ldap.yml
ansible-playbook -i inventory/hosts.ini setup/configure-aap-inventory.yml
ansible-playbook -i inventory/hosts.ini setup/configure-aap-project.yml --tags ee,project,section1
ansible-playbook -i inventory/hosts.ini setup/configure-aap-inventory.yml ## Bring in SCM details
ansible-playbook -i inventory/hosts.ini setup/configure-aap-podman-gateway-prereqs.yml
#ansible-playbook -i inventory/hosts.ini setup/configure-aap-project.yml --tags rbac


echo ""
echo "✓ control setup complete"
