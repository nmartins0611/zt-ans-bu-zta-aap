#!/bin/bash
set -euo pipefail

###############################################################################
# Helpers
###############################################################################

retry() {
    local max_attempts=2
    local delay=2
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
# 2. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control aap.zta.lab"
ensure_hosts_entry "192.168.1.11" "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"
ensure_hosts_entry "192.168.1.13" "wazuh.zta.lab wazuh"

###############################################################################
# 3. Network configuration (idempotent)
###############################################################################

ensure_nmcli_connection "enp2s0" \
    type ethernet con-name enp2s0 ifname enp2s0 \
    ipv4.addresses 192.168.1.13/24 \
    ipv4.method manual \
    ipv4.dns 192.168.1.11 \
    ipv4.dns-search zta.lab \
    connection.autoconnect yes

nmcli connection up enp2s0 || true

###############################################################################
# 4. Clean repos & subscriptions (only if not registered)
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
# 5. Register with Satellite
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
# 6. Install packages
###############################################################################

run_if_needed "Install required packages" \
    rpm -q python3-libsemanage ansible-core git podman \
    -- \
    dnf install -y python3-libsemanage ansible-core git podman

###############################################################################
# 7. Write Wazuh deployment playbook
###############################################################################

WAZ_PLAYBOOK="/tmp/waz-setup.yml"

tee "$WAZ_PLAYBOOK" > /dev/null << 'EOF'
---
- name: Wazuh All-in-One Deployment with SOC Analyst User
  hosts: localhost
  connection: local
  become: true
  gather_facts: true

  vars:
    wazuh_version: "4.14"
    soc_user: "soc-analyst"
    soc_password: "ansible123!"
    wazuh_install_script: "https://packages.wazuh.com/{{ wazuh_version }}/wazuh-install.sh"
    wazuh_api_port: 55000
    wazuh_indexer_port: 9200
    credentials_output_file: /root/wazuh-credentials.txt

  tasks:
    - name: Validate target is a RHEL-based system
      ansible.builtin.assert:
        that:
          - ansible_os_family == "RedHat"
        fail_msg: "This playbook targets RHEL-based systems only. Detected: {{ ansible_os_family }}"

    - name: Ensure system meets minimum requirements
      ansible.builtin.assert:
        that:
          - ansible_memtotal_mb >= 3700
          - ansible_processor_vcpus >= 2
        fail_msg: >-
          Minimum requirements not met.
          RAM: {{ ansible_memtotal_mb }}MB (need >=4GB), CPUs: {{ ansible_processor_vcpus }} (need >=2)

    - name: Download Wazuh installation assistant
      ansible.builtin.get_url:
        url: "{{ wazuh_install_script }}"
        dest: /root/wazuh-install.sh
        mode: "0755"

    - name: Run Wazuh all-in-one installation
      ansible.builtin.command:
        cmd: bash /root/wazuh-install.sh -a
        creates: /var/ossec/bin/wazuh-control
      register: wazuh_install_output
      changed_when: wazuh_install_output.rc == 0
      timeout: 1800

    - name: Display full installation output
      ansible.builtin.debug:
        var: wazuh_install_output.stdout_lines
      when: wazuh_install_output is defined

    - name: Extract admin password from installation output
      ansible.builtin.set_fact:
        admin_password: >-
          {{ wazuh_install_output.stdout
             | regex_search('Password:\s*(\S+)', '\1')
             | first }}
      when: wazuh_install_output.stdout is defined

    - name: Display captured admin credentials
      ansible.builtin.debug:
        msg:
          - "============================================"
          - "  WAZUH ADMIN CREDENTIALS"
          - "============================================"
          - "  User:     admin"
          - "  Password: {{ admin_password }}"
          - "============================================"
      when: admin_password is defined

    - name: Extract passwords file from wazuh-install-files.tar
      ansible.builtin.command:
        cmd: tar -O -xvf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
      register: wazuh_all_passwords
      changed_when: false

    - name: Display all generated Wazuh passwords
      ansible.builtin.debug:
        msg: "{{ wazuh_all_passwords.stdout_lines }}"

    - name: Save all credentials to file on target
      ansible.builtin.copy:
        content: |
          ============================================
          WAZUH ALL-IN-ONE CREDENTIALS
          Generated: {{ ansible_date_time.iso8601 }}
          ============================================

          --- Admin Dashboard Credentials ---
          User:     admin
          Password: {{ admin_password }}

          --- All Generated Passwords ---
          {{ wazuh_all_passwords.stdout }}

        dest: "{{ credentials_output_file }}"
        mode: "0600"
        owner: root
        group: root

    - name: Extract Wazuh API admin password (wazuh user)
      ansible.builtin.set_fact:
        wazuh_api_password: >-
          {{ wazuh_all_passwords.stdout
             | regex_search("indexer_username: 'admin'\n\s*indexer_password: '([^']+)'", '\1')
             | default([admin_password], true)
             | first }}

    - name: Extract Wazuh API wazuh-wui password
      ansible.builtin.set_fact:
        wazuh_wui_password: >-
          {{ wazuh_all_passwords.stdout
             | regex_search("api_username: 'wazuh-wui'\n\s*api_password: '([^']+)'", '\1')
             | first }}

    - name: Wait for Wazuh Indexer to be ready
      ansible.builtin.uri:
        url: "https://localhost:{{ wazuh_indexer_port }}/"
        method: GET
        user: admin
        password: "{{ admin_password }}"
        force_basic_auth: true
        validate_certs: false
        status_code: 200
      register: indexer_health
      retries: 30
      delay: 10
      until: indexer_health.status == 200

    - name: Wait for Wazuh API to be ready
      ansible.builtin.uri:
        url: "https://localhost:{{ wazuh_api_port }}/"
        method: GET
        validate_certs: false
        status_code: [200, 401]
      register: api_health
      retries: 30
      delay: 10
      until: api_health.status in [200, 401]

    - name: Authenticate to Wazuh API and obtain JWT token
      ansible.builtin.uri:
        url: "https://localhost:{{ wazuh_api_port }}/security/user/authenticate"
        method: POST
        user: "wazuh-wui"
        password: "{{ wazuh_wui_password }}"
        force_basic_auth: true
        validate_certs: false
        return_content: true
        headers:
          Content-Type: application/json
      register: wazuh_api_auth

    - name: Set API auth token
      ansible.builtin.set_fact:
        wazuh_api_token: "{{ wazuh_api_auth.json.data.token }}"

    - name: Create soc-analyst user in Wazuh API
      ansible.builtin.uri:
        url: "https://localhost:{{ wazuh_api_port }}/security/users"
        method: POST
        validate_certs: false
        headers:
          Authorization: "Bearer {{ wazuh_api_token }}"
          Content-Type: application/json
        body_format: json
        body:
          username: "{{ soc_user }}"
          password: "{{ soc_password }}"
        status_code: [200]
      register: api_user_created

    - name: Display API user creation result
      ansible.builtin.debug:
        msg: "Wazuh API user '{{ soc_user }}' created with ID: {{ api_user_created.json.data.affected_items[0].id }}"

    - name: Get list of API roles
      ansible.builtin.uri:
        url: "https://localhost:{{ wazuh_api_port }}/security/roles"
        method: GET
        validate_certs: false
        headers:
          Authorization: "Bearer {{ wazuh_api_token }}"
          Content-Type: application/json
      register: api_roles

    - name: Find the readonly role ID
      ansible.builtin.set_fact:
        readonly_role_id: >-
          {{ api_roles.json.data.affected_items
             | selectattr('name', 'equalto', 'readonly')
             | map(attribute='id')
             | first }}

    - name: Assign readonly role to soc-analyst in Wazuh API
      ansible.builtin.uri:
        url: "https://localhost:{{ wazuh_api_port }}/security/users/{{ api_user_created.json.data.affected_items[0].id }}/roles?role_ids={{ readonly_role_id }}"
        method: POST
        validate_certs: false
        headers:
          Authorization: "Bearer {{ wazuh_api_token }}"
          Content-Type: application/json
        status_code: [200]
      register: api_role_assigned

    - name: Create soc-analyst user in Wazuh Indexer
      ansible.builtin.uri:
        url: "https://localhost:{{ wazuh_indexer_port }}/_plugins/_security/api/internalusers/{{ soc_user }}"
        method: PUT
        user: admin
        password: "{{ admin_password }}"
        force_basic_auth: true
        validate_certs: false
        body_format: json
        body:
          password: "{{ soc_password }}"
          backend_roles:
            - "readall"
          description: "SOC Analyst user for security monitoring"
        status_code: [200, 201]
      register: indexer_user_created

    - name: Map soc-analyst to readall role in Wazuh Indexer
      ansible.builtin.uri:
        url: "https://localhost:{{ wazuh_indexer_port }}/_plugins/_security/api/rolesmapping/readall"
        method: PATCH
        user: admin
        password: "{{ admin_password }}"
        force_basic_auth: true
        validate_certs: false
        body_format: json
        body:
          - op: "add"
            path: "/users"
            value:
              - "{{ soc_user }}"
        status_code: [200]

    - name: Map soc-analyst to kibana_user role for dashboard access
      ansible.builtin.uri:
        url: "https://localhost:{{ wazuh_indexer_port }}/_plugins/_security/api/rolesmapping/kibana_user"
        method: PATCH
        user: admin
        password: "{{ admin_password }}"
        force_basic_auth: true
        validate_certs: false
        body_format: json
        body:
          - op: "add"
            path: "/users"
            value:
              - "{{ soc_user }}"
        status_code: [200]

    - name: Disable Wazuh YUM repository
      ansible.builtin.replace:
        path: /etc/yum.repos.d/wazuh.repo
        regexp: '^enabled=1'
        replace: 'enabled=0'
      when: ansible_pkg_mgr in ['yum', 'dnf']

    - name: Append soc-analyst credentials to saved credentials file
      ansible.builtin.blockinfile:
        path: "{{ credentials_output_file }}"
        marker: "# {mark} SOC ANALYST USER"
        block: |

          --- SOC Analyst User ---
          User:     {{ soc_user }}
          Password: {{ soc_password }}
          API Role: readonly
          Dashboard Roles: readall, kibana_user

    - name: Print final summary
      ansible.builtin.debug:
        msg:
          - "============================================================"
          - "  WAZUH ALL-IN-ONE INSTALLATION COMPLETE"
          - "============================================================"
          - ""
          - "  Dashboard URL: https://{{ ansible_default_ipv4.address }}"
          - ""
          - "  --- Admin Credentials ---"
          - "  User:     admin"
          - "  Password: {{ admin_password }}"
          - ""
          - "  --- SOC Analyst Credentials ---"
          - "  User:     {{ soc_user }}"
          - "  Password: {{ soc_password }}"
          - ""
          - "  All passwords saved to:"
          - "    Remote: {{ credentials_output_file }}"
          - ""
          - "============================================================"
EOF

###############################################################################
# 8. Run Wazuh deployment playbook
###############################################################################

export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

ansible-playbook "$WAZ_PLAYBOOK"

echo "wazuh setup complete"
