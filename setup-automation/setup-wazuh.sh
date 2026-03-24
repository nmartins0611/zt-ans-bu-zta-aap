#!/bin/bash
set -euo pipefail

###############################################################################
# Helpers
###############################################################################

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
# 2. Disable tmpfiles service (idempotent)
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
# 3. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control"
ensure_hosts_entry "192.168.1.11" "central.zta.lab keycloak.zta.lab opa.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.13" "wazuh.zta.lab wazuh"
ensure_hosts_entry "192.168.1.14" "node01.zta.lab node01"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"

###############################################################################
# 4. Network configuration (idempotent)
###############################################################################

ensure_nmcli_connection "enp2s0" \
    type ethernet con-name enp2s0 ifname enp2s0 \
    ipv4.addresses 192.168.1.13/24 \
    ipv4.method manual \
    connection.autoconnect yes

nmcli con mod enp2s0 ipv4.dns 192.168.1.11
nmcli con mod enp2s0 ipv4.dns-search zta.lab
nmcli connection up enp2s0 || true

###############################################################################
# 5. Clean repos & subscriptions (only if not registered)
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
# 6. Register with Satellite
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
# 7. Install packages
###############################################################################

run_if_needed "Install Python3 libraries" \
    rpm -q python3-libsemanage \
    -- \
    dnf install -y python3-libsemanage ansible-core git podman

###############################################################################
# 8. Wazuh deployment playbook
###############################################################################

tee /tmp/waz-setup.yml << 'EOF'
---
- name: Wazuh All-in-One Deployment with SOC Analyst User
  hosts: wazuh
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

    - name: Fetch credentials file to controller
      ansible.builtin.fetch:
        src: "{{ credentials_output_file }}"
        dest: "./credentials/{{ inventory_hostname }}-wazuh-credentials.txt"
        flat: true

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
          - "    Local:  ./credentials/{{ inventory_hostname }}-wazuh-credentials.txt"
          - ""
          - "============================================================"
EOF


tee /tmp/zta-splunk_vars.yml << 'EOF'
---
# Splunk container configuration
splunk_container_name: splunk
splunk_image: splunk/splunk:latest
splunk_privileged: true

# Port configuration
splunk_host_port: 8000
splunk_container_port: 8000

# Syslog port configuration
splunk_syslog_host_port: 5514
splunk_syslog_container_port: 5514

# Additional syslog port configuration
splunk_syslog_alt_host_port: 1514
splunk_syslog_alt_container_port: 1514

# HTTP Event Collector port configuration
splunk_hec_host_port: 8088
splunk_hec_container_port: 8088

# Authentication configuration
splunk_password: "{{ common_password | default('admin123') }}"

# Data directory configuration
splunk_data_dir: /opt/splunk-data
splunk_container_data_dir: /opt/splunk/var

# Splunk startup configuration
splunk_start_args: "--accept-license"
splunk_general_terms: "--accept-sgt-current-at-splunk-com"

# Splunk apps to install (list of apps)
splunk_apps:
  - url: "https://my-splunk-apps.s3.us-east-1.amazonaws.com/apps/red-hat-event-driven-ansible-add-on-for-splunk_101.tgz"
    filename: "red-hat-event-driven-ansible-add-on-for-splunk_101.tgz"

splunk_container_apps_path: "/opt/splunk/etc/apps/"
splunk_app_owner: "splunk"
splunk_app_group: "splunk"

# Systemd service configuration
splunk_service_enable: true
splunk_service_name: "container-{{ splunk_container_name }}"


EOF

tee /tmp/zta-splunk.yml << 'EOF'
---
- name: Deploy Splunk Container
  hosts: localhost
  become: true
  gather_facts: true

  # FIXED: Use vars_files for play-level variable inclusion
  vars_files:
    - zta-splunk_vars.yml

  tasks:
    # FIXED: Indented all tasks by 2 spaces relative to 'tasks:'
    - name: Create Splunk data directories
      ansible.builtin.file:
        path: "{{ item }}"
        state: directory
        mode: '0755'
        owner: root
        group: root
      loop:
        - "{{ splunk_data_dir }}"
        - "{{ splunk_data_dir }}/var"
        - "{{ splunk_data_dir }}/etc"
        - "{{ splunk_data_dir }}/etc/apps"

    - name: Stop any existing Splunk container
      containers.podman.podman_container:
        name: "{{ splunk_container_name }}"
        state: absent
      failed_when: false

    - name: Run Splunk container
      containers.podman.podman_container:
        name: "{{ splunk_container_name }}"
        image: "{{ splunk_image }}"
        state: started
        ports:
          - "{{ splunk_host_port }}:{{ splunk_container_port }}"
          - "{{ splunk_syslog_host_port }}:{{ splunk_syslog_container_port }}/tcp"
          - "{{ splunk_syslog_host_port }}:{{ splunk_syslog_container_port }}/udp"
          - "{{ splunk_syslog_alt_host_port }}:{{ splunk_syslog_alt_container_port }}/tcp"
          - "{{ splunk_syslog_alt_host_port }}:{{ splunk_syslog_alt_container_port }}/udp"
          - "{{ splunk_hec_host_port }}:{{ splunk_hec_container_port }}"
        privileged: "{{ splunk_privileged }}"
        env:
          SPLUNK_START_ARGS: "{{ splunk_start_args }}"
          SPLUNK_GENERAL_TERMS: "{{ splunk_general_terms }}"
          SPLUNK_PASSWORD: "{{ splunk_password }}"
        volume:
          - "{{ splunk_data_dir }}/var:/opt/splunk/var"
          - "{{ splunk_data_dir }}/etc:/opt/splunk/etc"
        detach: true

    - name: Wait for Splunk to be ready
      ansible.builtin.uri:
        url: "http://localhost:{{ splunk_host_port }}"
        method: GET
        status_code: [200, 302]
      register: splunk_health_check
      until: splunk_health_check.status in [200, 302]
      retries: 20
      delay: 5
      ignore_errors: true

    - name: Create temporary directory for Splunk apps
      ansible.builtin.tempfile:
        state: directory
        suffix: splunk_apps
      register: temp_apps_dir

    - name: Download Splunk apps from S3
      ansible.builtin.get_url:
        url: "{{ item.url }}"
        dest: "{{ temp_apps_dir.path }}/{{ item.filename }}"
        mode: '0644'
      loop: "{{ splunk_apps }}"

    # FIXED: Replaced non-existent podman modules. 
    # Extracting directly to the host's mapped volume is safer, native to Ansible, and faster.
    - name: Extract Splunk apps directly to mapped etc/apps volume
      ansible.builtin.unarchive:
        src: "{{ temp_apps_dir.path }}/{{ item.filename }}"
        dest: "{{ splunk_data_dir }}/etc/apps/"
        remote_src: yes
        owner: "{{ splunk_app_owner }}"
        group: "{{ splunk_app_group }}"
      loop: "{{ splunk_apps }}"

    - name: Clean up temporary directory
      ansible.builtin.file:
        path: "{{ temp_apps_dir.path }}"
        state: absent

    - name: Restart Splunk container to load the apps
      containers.podman.podman_container:
        name: "{{ splunk_container_name }}"
        state: started
        restart: true

    - name: Wait for Splunk to be ready after restart
      ansible.builtin.uri:
        url: "http://localhost:{{ splunk_host_port }}"
        method: GET
        status_code: [200, 302]
      register: splunk_health_check_restart
      until: splunk_health_check_restart.status in [200, 302]
      retries: 20
      delay: 5

    - name: Generate systemd service file for Splunk container
      containers.podman.podman_generate_systemd:
        name: "{{ splunk_container_name }}"
        dest: /etc/systemd/system/
        restart_policy: always
        new: false
      when: splunk_service_enable | bool

    - name: Enable and start Splunk systemd service
      ansible.builtin.systemd:
        name: "{{ splunk_service_name }}"
        enabled: true
        state: started
        daemon_reload: true
      when: splunk_service_enable | bool

    - name: Display Splunk access information
      ansible.builtin.debug:
        msg:
          - "Splunk is now running and accessible at:"
          - "URL: http://{{ ansible_default_ipv4.address }}:{{ splunk_host_port }}"
          - "Username: admin"
          - "Password: {{ splunk_password }}"
          - ""
          - "Installed apps:"
          - "{{ splunk_apps | map(attribute='filename') | list }}"
          - ""
          - "Systemd service: {{ splunk_service_name }}"
          - "Check status: systemctl status {{ splunk_service_name }}"
          - "View logs: journalctl -u {{ splunk_service_name }} -f"

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

export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

rm -rf ~/.ansible.cfg

echo "✓ wazuh setup complete"
