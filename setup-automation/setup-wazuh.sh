#!/bin/bash

systemctl stop systemd-tmpfiles-setup.service
systemctl disable systemd-tmpfiles-setup.service

nmcli connection add type ethernet con-name eth1 ifname eth1 ipv4.addresses 192.168.1.10/24 ipv4.method manual connection.autoconnect yes
nmcli connection up eth1
echo "192.168.1.10 control.lab control" >> /etc/hosts

rm -rf /etc/yum.repos.d/*
yum clean all
subcription-manager clean

curl -k  -L https://${SATELLITE_URL}/pub/katello-server-ca.crt -o /etc/pki/ca-trust/source/anchors/${SATELLITE_URL}.ca.crt
update-ca-trust
rpm -Uhv https://${SATELLITE_URL}/pub/katello-ca-consumer-latest.noarch.rpm
subscription-manager register --org=${SATELLITE_ORG} --activationkey=${SATELLITE_ACTIVATIONKEY}

##
########
## install python3 libraries needed for the Cloud Report
dnf install -y python3-pip python3-libsemanage

# Create a playbook for the user to execute
tee /tmp/waz-setup.yml << EOF
### Wazuh setup
###
---
# =============================================================================
# Wazuh All-in-One Installation on RHEL + SOC Analyst User Creation
# =============================================================================
#
# This playbook:
#   1. Installs Wazuh (server, indexer, dashboard) on a single RHEL host
#   2. Captures the generated admin credentials
#   3. Extracts all generated passwords from wazuh-install-files.tar
#   4. Creates a "soc-analyst" user in the Wazuh API and Wazuh Indexer
#   5. Maps the soc-analyst user to appropriate roles for dashboard access
#
# Usage:
#   ansible-playbook -i inventory.ini wazuh-aio.yml
#
# =============================================================================

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
    # =========================================================================
    # Pre-flight checks
    # =========================================================================
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

    # =========================================================================
    # Install Wazuh All-in-One
    # =========================================================================
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

    # =========================================================================
    # Capture admin credentials from install output
    # =========================================================================
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

    # =========================================================================
    # Extract ALL passwords from wazuh-install-files.tar
    # =========================================================================
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

    # =========================================================================
    # Extract Wazuh API credentials (wazuh / wazuh-wui)
    # =========================================================================
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

    # =========================================================================
    # Wait for services to be fully ready
    # =========================================================================
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

    # =========================================================================
    # Create SOC Analyst user in Wazuh API (port 55000)
    # =========================================================================
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

    - name: Find the 'readonly' role ID
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

    # =========================================================================
    # Create SOC Analyst user in Wazuh Indexer (for Dashboard login)
    # =========================================================================
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

    # =========================================================================
    # Disable Wazuh repo to prevent accidental upgrades (recommended)
    # =========================================================================
    - name: Disable Wazuh YUM repository
      ansible.builtin.replace:
        path: /etc/yum.repos.d/wazuh.repo
        regexp: '^enabled=1'
        replace: 'enabled=0'
      when: ansible_pkg_mgr in ['yum', 'dnf']

    # =========================================================================
    # Append soc-analyst credentials to the saved file
    # =========================================================================
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

    # =========================================================================
    # Fetch credentials file to Ansible controller
    # =========================================================================
    - name: Fetch credentials file to controller
      ansible.builtin.fetch:
        src: "{{ credentials_output_file }}"
        dest: "./credentials/{{ inventory_hostname }}-wazuh-credentials.txt"
        flat: true

    # =========================================================================
    # Final summary
    # =========================================================================
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
export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

#ANSIBLE_COLLECTIONS_PATH=/root/ansible-automation-platform-containerized-setup/collections/ansible_collections ansible-playbook -i /tmp/inventory /tmp/setup.yml
