#!/bin/bash

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
[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
pipelining = True
EOF

tee /tmp/requirements.yml > /dev/null <<EOF
---
collections:
  - name: community.general
    version: ">=3.0.0"

  - name: ansible.posix
    version: ">=1.0.0"

  - name: community.docker
    version: ">=3.0.0"

EOF

tee /tmp/inventory > /dev/null <<EOF

[local]
localhost ansible_connection=local

[control]
control ansible_connection=local

[central]
central

[vault]
vault

[wazuh]
wazuh

[netbox]
netbox

[zta:children]
control
central
vault
wazuh
netbox

[zta:vars]
ansible_user=rhel
ansible_password=ansible123!
ansible_become=true

EOF

tee /tmp/lab_setup.yml > /dev/null <<EOF
---
# Master Playbook - Runs from Control Node
# This playbook configures all ZTA lab nodes remotely from the control machine
#
# Usage: ansible-playbook -i inventory.ini master-playbook.yml
#
# Required environment variables:
# - TMM_ORG: Subscription Manager Organization ID
# - TMM_ID: Subscription Manager Activation Key
# - AH_TOKEN: Ansible Automation Hub token (for central node)
# - VAULT_LIC: Vault license content (for vault node)
# - VAULT_UNSEAL_KEY: Vault unseal key (for vault node)
# - GUID: (Optional) GUID for Keycloak hostname
# - DOMAIN: (Optional) Domain for Keycloak hostname

- name: Display Setup Information
  hosts: localhost
  gather_facts: false

  tasks:
    - name: Display setup banner
      ansible.builtin.debug:
        msg: |
          ============================================
          ZTA Lab Complete Setup - Master Playbook
          ============================================
          Running from: Control Node
          Target nodes:
          - Control Node (192.168.1.10) - control.zta.lab
          - Central Node (192.168.1.11) - central.zta.lab
          - Vault Node (192.168.1.12) - vault.zta.lab
          - Wazuh Node (192.168.1.13) - wazuh.zta.lab
          - NetBox Node (192.168.1.15) - netbox.zta.lab

          Ensure all required environment variables are set
          ============================================

    - name: Validate required environment variables
      ansible.builtin.assert:
        that:
          - lookup('env', 'TMM_ORG') | length > 0
          - lookup('env', 'TMM_ID') | length > 0
        fail_msg: "Required environment variables TMM_ORG and TMM_ID must be set"

# =============================================================================
# CONTROL NODE SETUP
# =============================================================================
- name: Setup Control Node
  hosts: control
  become: true
  gather_facts: true
  tags:
    - control
    - setup

  vars:
    tmm_org: "{{ lookup('env', 'TMM_ORG') }}"
    tmm_id: "{{ lookup('env', 'TMM_ID') }}"
    interface_name: eth1
    ip_address: 192.168.1.10/24
    dns_server: 192.168.1.11
    dns_search: zta.lab

  tasks:
    - name: Set SELinux to permissive mode
      ansible.posix.selinux:
        policy: targeted
        state: permissive
      when: ansible_selinux.status == "enabled"

    - name: Check if system is already registered
      ansible.builtin.command: subscription-manager identity
      register: sub_check
      failed_when: false
      changed_when: false

    - name: Clean subscription data if not registered
      ansible.builtin.command: subscription-manager clean
      when: sub_check.rc != 0

    - name: Register system with subscription-manager
      community.general.redhat_subscription:
        org_id: "{{ tmm_org }}"
        activationkey: "{{ tmm_id }}"
        force_register: true
      when: sub_check.rc != 0

    - name: Enable repository management
      ansible.builtin.command: subscription-manager config --rhsm.manage_repos=1
      when: sub_check.rc != 0
      changed_when: false

    - name: Refresh subscription
      ansible.builtin.command: subscription-manager refresh
      when: sub_check.rc != 0
      changed_when: false

    - name: Install base packages
      ansible.builtin.dnf:
        name:
          - dnf-utils
          - git
          - nano
        state: present
      tags:
        - packages

    - name: Install IPA client packages
      ansible.builtin.dnf:
        name:
          - ipa-client
          - sssd
          - oddjob-mkhomedir
        state: present
      tags:
        - packages
        - ipa

    - name: Install Python3 libraries
      ansible.builtin.dnf:
        name:
          - python3-libsemanage
        state: present
      tags:
        - packages

    - name: Add hosts entries
      ansible.builtin.lineinfile:
        path: /etc/hosts
        line: "{{ item.ip }} {{ item.names }}"
        regexp: "^{{ item.ip }} "
        state: present
      loop:
        - { ip: "192.168.1.10", names: "control.zta.lab control aap.zta.lab" }
        - { ip: "192.168.1.11", names: "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab" }
        - { ip: "192.168.1.12", names: "vault.zta.lab vault" }
        - { ip: "192.168.1.15", names: "netbox.zta.lab netbox" }
        - { ip: "192.168.1.13", names: "wazuh.zta.lab wazuh" }
      tags:
        - network
        - hosts

    - name: Configure network connection
      community.general.nmcli:
        conn_name: "{{ interface_name }}"
        ifname: "{{ interface_name }}"
        type: ethernet
        ip4: "{{ ip_address }}"
        dns4: "{{ dns_server }}"
        dns4_search: "{{ dns_search }}"
        autoconnect: true
        state: present
      tags:
        - network

    - name: Activate network connection
      ansible.builtin.command: nmcli connection up {{ interface_name }}
      register: nmcli_up
      failed_when: false
      changed_when: nmcli_up.rc == 0
      tags:
        - network

    - name: Control node setup complete
      ansible.builtin.debug:
        msg: "✓ Control node ({{ ansible_hostname }}) setup complete"

# =============================================================================
# VAULT NODE SETUP
# =============================================================================
- name: Setup Vault Node
  hosts: vault
  become: true
  gather_facts: true
  tags:
    - vault
    - setup

  vars:
    tmm_org: "{{ lookup('env', 'TMM_ORG') }}"
    tmm_id: "{{ lookup('env', 'TMM_ID') }}"
    vault_lic: "{{ lookup('env', 'VAULT_LIC') }}"
    vault_unseal_key: "{{ lookup('env', 'VAULT_UNSEAL_KEY') }}"
    interface_name: eth1
    ip_address: 192.168.1.12/24

  tasks:
    - name: Validate Vault environment variables
      ansible.builtin.assert:
        that:
          - vault_lic | length > 0
          - vault_unseal_key | length > 0
        fail_msg: "Required environment variables VAULT_LIC and VAULT_UNSEAL_KEY must be set"
      tags:
        - always

    - name: Set SELinux to permissive mode
      ansible.posix.selinux:
        policy: targeted
        state: permissive
      when: ansible_selinux.status == "enabled"
      tags:
        - selinux

    - name: Check if system is already registered
      ansible.builtin.command: subscription-manager identity
      register: sub_check
      failed_when: false
      changed_when: false
      tags:
        - subscription

    - name: Clean subscription data if not registered
      ansible.builtin.command: subscription-manager clean
      when: sub_check.rc != 0
      tags:
        - subscription

    - name: Register system with subscription-manager
      community.general.redhat_subscription:
        org_id: "{{ tmm_org }}"
        activationkey: "{{ tmm_id }}"
        force_register: true
      when: sub_check.rc != 0
      tags:
        - subscription

    - name: Enable repository management
      ansible.builtin.command: subscription-manager config --rhsm.manage_repos=1
      when: sub_check.rc != 0
      changed_when: false
      tags:
        - subscription

    - name: Refresh subscription
      ansible.builtin.command: subscription-manager refresh
      when: sub_check.rc != 0
      changed_when: false
      tags:
        - subscription

    - name: Create Vault license file
      ansible.builtin.copy:
        content: "{{ vault_lic }}"
        dest: /opt/vault/vault.hclic
        mode: '0600'
      tags:
        - vault-config

    - name: Restart Vault service
      ansible.builtin.systemd:
        name: vault
        state: restarted
      failed_when: false
      tags:
        - vault-config

    - name: Wait for Vault service to start
      ansible.builtin.wait_for:
        port: 8200
        delay: 5
        timeout: 60
      tags:
        - vault-config

    - name: Unseal Vault
      ansible.builtin.uri:
        url: http://localhost:8200/v1/sys/unseal
        method: POST
        body_format: json
        body:
          key: "{{ vault_unseal_key }}"
        status_code: 200
      register: unseal_result
      until: unseal_result.status == 200
      retries: 3
      delay: 5
      tags:
        - vault-config

    - name: Add hosts entries
      ansible.builtin.lineinfile:
        path: /etc/hosts
        line: "{{ item.ip }} {{ item.names }}"
        regexp: "^{{ item.ip }} "
        state: present
      loop:
        - { ip: "192.168.1.10", names: "control.zta.lab control aap.zta.lab" }
        - { ip: "192.168.1.11", names: "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab" }
        - { ip: "192.168.1.12", names: "vault.zta.lab vault" }
        - { ip: "192.168.1.15", names: "netbox.zta.lab netbox" }
        - { ip: "192.168.1.13", names: "wazuh.zta.lab wazuh" }
      tags:
        - network
        - hosts

    - name: Configure network connection
      community.general.nmcli:
        conn_name: "{{ interface_name }}"
        ifname: "{{ interface_name }}"
        type: ethernet
        ip4: "{{ ip_address }}"
        autoconnect: true
        state: present
      tags:
        - network

    - name: Activate network connection
      ansible.builtin.command: nmcli connection up {{ interface_name }}
      register: nmcli_up
      failed_when: false
      changed_when: nmcli_up.rc == 0
      tags:
        - network

    - name: Vault node setup complete
      ansible.builtin.debug:
        msg: "✓ Vault node ({{ ansible_hostname }}) setup complete"

# =============================================================================
# NETBOX NODE SETUP
# =============================================================================
- name: Setup NetBox Node
  hosts: netbox
  become: true
  gather_facts: true
  tags:
    - netbox
    - setup

  vars:
    tmm_org: "{{ lookup('env', 'TMM_ORG') }}"
    tmm_id: "{{ lookup('env', 'TMM_ID') }}"
    interface_name: eth1
    ip_address: 192.168.1.15/24
    netbox_dir: /opt/netbox-docker

  tasks:
    - name: Set SELinux to permissive mode
      ansible.posix.selinux:
        policy: targeted
        state: permissive
      when: ansible_selinux.status == "enabled"
      tags:
        - selinux

    - name: Check if system is already registered
      ansible.builtin.command: subscription-manager identity
      register: sub_check
      failed_when: false
      changed_when: false
      tags:
        - subscription

    - name: Clean subscription data if not registered
      ansible.builtin.command: subscription-manager clean
      when: sub_check.rc != 0
      tags:
        - subscription

    - name: Register system with subscription-manager
      community.general.redhat_subscription:
        org_id: "{{ tmm_org }}"
        activationkey: "{{ tmm_id }}"
        force_register: true
      when: sub_check.rc != 0
      tags:
        - subscription

    - name: Enable repository management
      ansible.builtin.command: subscription-manager config --rhsm.manage_repos=1
      when: sub_check.rc != 0
      changed_when: false
      tags:
        - subscription

    - name: Refresh subscription
      ansible.builtin.command: subscription-manager refresh
      when: sub_check.rc != 0
      changed_when: false
      tags:
        - subscription

    - name: Install base packages
      ansible.builtin.dnf:
        name:
          - dnf-utils
          - git
          - nano
        state: present
      tags:
        - packages

    - name: Install Docker and dependencies
      ansible.builtin.dnf:
        name:
          - dnf-plugins-core
          - device-mapper-persistent-data
          - lvm2
        state: present
      tags:
        - packages
        - docker

    - name: Add Docker CE repository
      ansible.builtin.command: >
        dnf config-manager --add-repo
        https://download.docker.com/linux/centos/docker-ce.repo
      args:
        creates: /etc/yum.repos.d/docker-ce.repo
      tags:
        - docker

    - name: Install Docker CE
      ansible.builtin.dnf:
        name:
          - docker-ce
          - docker-ce-cli
          - containerd.io
          - docker-compose-plugin
        state: present
      tags:
        - packages
        - docker

    - name: Start and enable Docker service
      ansible.builtin.systemd:
        name: docker
        state: started
        enabled: true
      tags:
        - docker

    - name: Clone netbox-docker repository
      ansible.builtin.git:
        repo: https://github.com/netbox-community/netbox-docker.git
        dest: "{{ netbox_dir }}"
        version: release
      tags:
        - netbox-config

    - name: Create docker-compose override file
      ansible.builtin.copy:
        content: |
          version: '3.4'
          services:
            netbox:
              ports:
                - 8000:8080
        dest: "{{ netbox_dir }}/docker-compose.override.yml"
        mode: '0644'
      tags:
        - netbox-config

    - name: Start NetBox containers
      community.docker.docker_compose_v2:
        project_src: "{{ netbox_dir }}"
        state: present
      register: netbox_compose
      tags:
        - docker
        - netbox-config

    - name: Add hosts entries
      ansible.builtin.lineinfile:
        path: /etc/hosts
        line: "{{ item.ip }} {{ item.names }}"
        regexp: "^{{ item.ip }} "
        state: present
      loop:
        - { ip: "192.168.1.10", names: "control.zta.lab control aap.zta.lab" }
        - { ip: "192.168.1.11", names: "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab" }
        - { ip: "192.168.1.12", names: "vault.zta.lab vault" }
        - { ip: "192.168.1.15", names: "netbox.zta.lab netbox" }
        - { ip: "192.168.1.13", names: "wazuh.zta.lab wazuh" }
      tags:
        - network
        - hosts

    - name: Configure network connection
      community.general.nmcli:
        conn_name: "{{ interface_name }}"
        ifname: "{{ interface_name }}"
        type: ethernet
        ip4: "{{ ip_address }}"
        autoconnect: true
        state: present
      tags:
        - network

    - name: Activate network connection
      ansible.builtin.command: nmcli connection up {{ interface_name }}
      register: nmcli_up
      failed_when: false
      changed_when: nmcli_up.rc == 0
      tags:
        - network

    - name: NetBox node setup complete
      ansible.builtin.debug:
        msg: "✓ NetBox node ({{ ansible_hostname }}) setup complete"

# =============================================================================
# WAZUH NODE SETUP
# =============================================================================
- name: Setup Wazuh Node
  hosts: wazuh
  become: true
  gather_facts: true
  tags:
    - wazuh
    - setup

  vars:
    tmm_org: "{{ lookup('env', 'TMM_ORG') }}"
    tmm_id: "{{ lookup('env', 'TMM_ID') }}"
    interface_name: enp2s0
    ip_address: 192.168.1.13/24

  tasks:
    - name: Set SELinux to permissive mode
      ansible.posix.selinux:
        policy: targeted
        state: permissive
      when: ansible_selinux.status == "enabled"
      tags:
        - selinux

    - name: Check if system is already registered
      ansible.builtin.command: subscription-manager identity
      register: sub_check
      failed_when: false
      changed_when: false
      tags:
        - subscription

    - name: Clean subscription data if not registered
      ansible.builtin.command: subscription-manager clean
      when: sub_check.rc != 0
      tags:
        - subscription

    - name: Register system with subscription-manager
      community.general.redhat_subscription:
        org_id: "{{ tmm_org }}"
        activationkey: "{{ tmm_id }}"
        force_register: true
      when: sub_check.rc != 0
      tags:
        - subscription

    - name: Enable repository management
      ansible.builtin.command: subscription-manager config --rhsm.manage_repos=1
      when: sub_check.rc != 0
      changed_when: false
      tags:
        - subscription

    - name: Refresh subscription
      ansible.builtin.command: subscription-manager refresh
      when: sub_check.rc != 0
      changed_when: false
      tags:
        - subscription

    - name: Install base packages
      ansible.builtin.dnf:
        name:
          - ansible-core
          - git
          - podman
        state: present
      tags:
        - packages

    - name: Add hosts entries
      ansible.builtin.lineinfile:
        path: /etc/hosts
        line: "{{ item.ip }} {{ item.names }}"
        regexp: "^{{ item.ip }} "
        state: present
      loop:
        - { ip: "192.168.1.10", names: "control.zta.lab control aap.zta.lab" }
        - { ip: "192.168.1.11", names: "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab" }
        - { ip: "192.168.1.12", names: "vault.zta.lab vault" }
        - { ip: "192.168.1.15", names: "netbox.zta.lab netbox" }
        - { ip: "192.168.1.13", names: "wazuh.zta.lab wazuh" }
      tags:
        - network
        - hosts

    - name: Configure network connection
      community.general.nmcli:
        conn_name: "{{ interface_name }}"
        ifname: "{{ interface_name }}"
        type: ethernet
        ip4: "{{ ip_address }}"
        autoconnect: true
        state: present
      tags:
        - network

    - name: Activate network connection
      ansible.builtin.command: nmcli connection up {{ interface_name }}
      register: nmcli_up
      failed_when: false
      changed_when: nmcli_up.rc == 0
      tags:
        - network

    - name: Wazuh node setup complete
      ansible.builtin.debug:
        msg: "✓ Wazuh node ({{ ansible_hostname }}) setup complete"

# =============================================================================
# CENTRAL NODE SETUP
# =============================================================================
- name: Setup Central Node
  hosts: central
  become: true
  gather_facts: true
  tags:
    - central
    - setup

  vars:
    tmm_org: "{{ lookup('env', 'TMM_ORG') }}"
    tmm_id: "{{ lookup('env', 'TMM_ID') }}"
    ah_token: "{{ lookup('env', 'AH_TOKEN') }}"
    guid: "{{ lookup('env', 'GUID') | default('default', true) }}"
    domain: "{{ lookup('env', 'DOMAIN') | default('local', true) }}"
    netbox_token: "0123456789abcdef0123456789abcdef01234567"
    interface_name: enp2s0
    ip_address: 192.168.1.11/24
    workshop_repo_dir: /tmp/zta-workshop-aap
    ipa_rewrite_file: /etc/httpd/conf.d/ipa-rewrite.conf

  tasks:
    - name: Validate Central node environment variables
      ansible.builtin.assert:
        that:
          - ah_token | length > 0
        fail_msg: "Required environment variable AH_TOKEN must be set"
      tags:
        - always

    - name: Stop firewalld
      ansible.builtin.systemd:
        name: firewalld
        state: stopped
      failed_when: false
      tags:
        - firewall

    - name: Set SELinux to permissive mode
      ansible.builtin.command: setenforce 0
      failed_when: false
      changed_when: false
      tags:
        - selinux

    - name: Remove existing workshop directory
      ansible.builtin.file:
        path: "{{ workshop_repo_dir }}"
        state: absent
      tags:
        - cleanup

    - name: Check if system is already registered
      ansible.builtin.command: subscription-manager identity
      register: sub_check
      failed_when: false
      changed_when: false
      tags:
        - subscription

    - name: Clean subscription data if not registered
      ansible.builtin.command: subscription-manager clean
      when: sub_check.rc != 0
      tags:
        - subscription

    - name: Register system with subscription-manager
      community.general.redhat_subscription:
        org_id: "{{ tmm_org }}"
        activationkey: "{{ tmm_id }}"
        force_register: true
      when: sub_check.rc != 0
      tags:
        - subscription

    - name: Enable repository management
      ansible.builtin.command: subscription-manager config --rhsm.manage_repos=1
      when: sub_check.rc != 0
      changed_when: false
      tags:
        - subscription

    - name: Refresh subscription
      ansible.builtin.command: subscription-manager refresh
      when: sub_check.rc != 0
      changed_when: false
      tags:
        - subscription

    - name: Install base packages
      ansible.builtin.dnf:
        name:
          - dnf-utils
          - git
          - nano
        state: present
      tags:
        - packages

    - name: Install system packages
      ansible.builtin.dnf:
        name:
          - python3-libsemanage
          - git
          - ansible-core
          - python-requests
          - ipa-client
          - sssd
          - oddjob-mkhomedir
          - python3-pip
          - unzip
        state: present
      tags:
        - packages

    - name: Download Flask wheels
      ansible.builtin.command: pip download flask -d /tmp/flask-wheels
      args:
        creates: /tmp/flask-wheels
      tags:
        - packages
        - python

    - name: Install Flask from local wheels
      ansible.builtin.pip:
        name: flask
        extra_args: --no-index --find-links /tmp/flask-wheels
      tags:
        - packages
        - python

    - name: Install pynetbox
      ansible.builtin.pip:
        name: pynetbox
        state: present
      tags:
        - packages
        - python

    - name: Download IPA RPMs
      ansible.builtin.command: dnf download --resolve --destdir /tmp/ipa-rpms ipa-client
      args:
        creates: /tmp/ipa-rpms
      tags:
        - ipa

    - name: Check if containers exist and install IPA client
      tags:
        - ipa
        - containers
      block:
        - name: Check if app container exists
          ansible.builtin.command: podman container exists app
          register: app_exists
          failed_when: false
          changed_when: false

        - name: Copy and install IPA RPMs to app container
          block:
            - name: Check if ipa-client already installed in app
              ansible.builtin.command: podman exec app rpm -q ipa-client
              register: app_ipa_check
              failed_when: false
              changed_when: false

            - name: Copy IPA RPMs to app container
              ansible.builtin.command: podman cp /tmp/ipa-rpms app:/tmp/ipa-rpms
              when: app_ipa_check.rc != 0

            - name: Install IPA RPMs in app container
              ansible.builtin.command: podman exec app bash -c 'dnf install -y /tmp/ipa-rpms/*.rpm && rm -rf /tmp/ipa-rpms'
              when: app_ipa_check.rc != 0
          when: app_exists.rc == 0

        - name: Check if db container exists
          ansible.builtin.command: podman container exists db
          register: db_exists
          failed_when: false
          changed_when: false

        - name: Copy and install IPA RPMs to db container
          block:
            - name: Check if ipa-client already installed in db
              ansible.builtin.command: podman exec db rpm -q ipa-client
              register: db_ipa_check
              failed_when: false
              changed_when: false

            - name: Copy IPA RPMs to db container
              ansible.builtin.command: podman cp /tmp/ipa-rpms db:/tmp/ipa-rpms
              when: db_ipa_check.rc != 0

            - name: Install IPA RPMs in db container
              ansible.builtin.command: podman exec db bash -c 'dnf install -y /tmp/ipa-rpms/*.rpm && rm -rf /tmp/ipa-rpms'
              when: db_ipa_check.rc != 0
          when: db_exists.rc == 0

    - name: Clone ZTA workshop repository
      ansible.builtin.git:
        repo: https://github.com/nmartins0611/zta-workshop-aap.git
        dest: "{{ workshop_repo_dir }}"
        version: zta-container
      tags:
        - workshop

    - name: Install Ansible collections
      community.general.ansible_galaxy_install:
        type: collection
        name: "{{ item }}"
      loop:
        - community.general
        - netbox.netbox
        - ansible.controller
      tags:
        - ansible
        - collections

    - name: Check if httpd is installed
      ansible.builtin.stat:
        path: /usr/sbin/httpd
      register: httpd_check
      tags:
        - ipa

    - name: Configure IPA rewrite if httpd exists
      tags:
        - ipa
      block:
        - name: Check if IPA rewrite already configured
          ansible.builtin.lineinfile:
            path: "{{ ipa_rewrite_file }}"
            line: "RequestHeader set Host central.zta.lab"
            state: present
          check_mode: true
          register: ipa_rewrite_check

        - name: Create IPA rewrite configuration
          ansible.builtin.copy:
            content: |
              # VERSION 7 - DO NOT REMOVE THIS LINE
              RequestHeader set Host central.zta.lab
              RequestHeader set Referer https://central.zta.lab/ipa/ui/
              RewriteEngine on
              RewriteRule ^/ipa/ui/js/freeipa/plugins.js$    /ipa/wsgi/plugins.py [PT]
              RewriteCond %{HTTP_HOST}    ^ipa-ca.example.local$ [NC]
              RewriteCond %{REQUEST_URI}  !^/ipa/crl
              RewriteCond %{REQUEST_URI}  !^/(ca|kra|pki|acme)
            dest: "{{ ipa_rewrite_file }}"
            mode: '0644'
          when: ipa_rewrite_check.changed
          notify: Reload httpd
      when: httpd_check.stat.exists

    - name: Stop existing Keycloak container
      ansible.builtin.command: podman stop keycloak
      failed_when: false
      changed_when: false
      tags:
        - keycloak
        - containers

    - name: Remove existing Keycloak container
      ansible.builtin.command: podman rm --force keycloak
      failed_when: false
      changed_when: false
      tags:
        - keycloak
        - containers

    - name: Create Keycloak container
      ansible.builtin.command: >
        podman create --name keycloak --restart=always -p 8180:8080 -p 8543:8443
        -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=ansible123!
        -e KC_HOSTNAME=keycloak-https-{{ guid }}.{{ domain }}
        -e KC_HTTPS_CERTIFICATE_FILE=/opt/certs/server.crt
        -e KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/certs/server.key
        -e KC_HTTP_ENABLED=true -v /opt/keycloak/certs:/opt/certs:Z
        registry.redhat.io/rhbk/keycloak-rhel9:24 start
        --hostname=keycloak-https-{{ guid }}.{{ domain }}
        --https-port=8443 --http-enabled=true --proxy-headers forwarded
      changed_when: true
      tags:
        - keycloak
        - containers

    - name: Check if container-keycloak systemd service exists
      ansible.builtin.stat:
        path: /etc/systemd/system/container-keycloak.service
      register: keycloak_service
      tags:
        - keycloak

    - name: Fix systemd service if it exists
      tags:
        - keycloak
      block:
        - name: Remove PIDFile line from systemd service
          ansible.builtin.lineinfile:
            path: /etc/systemd/system/container-keycloak.service
            regexp: "^PIDFile"
            state: absent
          notify:
            - Reload systemd
            - Start container-keycloak
      when: keycloak_service.stat.exists

    - name: Flush handlers
      ansible.builtin.meta: flush_handlers

    - name: Run DNS configuration playbook
      ansible.builtin.command: >
        ansible-playbook -i {{ workshop_repo_dir }}/inventory/hosts.ini
        {{ workshop_repo_dir }}/setup/configure-dns.yml
      environment:
        ANSIBLE_HOST_KEY_CHECKING: "False"
      tags:
        - workshop
        - dns

    - name: Run Vault configuration playbook
      ansible.builtin.command: >
        ansible-playbook -i {{ workshop_repo_dir }}/inventory/hosts.ini
        {{ workshop_repo_dir }}/setup/configure-vault.yml
      environment:
        ANSIBLE_HOST_KEY_CHECKING: "False"
      tags:
        - workshop
        - vault-config

    - name: Run Vault SSH configuration playbook
      ansible.builtin.command: >
        ansible-playbook -i {{ workshop_repo_dir }}/inventory/hosts.ini
        {{ workshop_repo_dir }}/setup/configure-vault-ssh.yml
      environment:
        ANSIBLE_HOST_KEY_CHECKING: "False"
      tags:
        - workshop
        - vault-config

    - name: Run IDM client enrollment playbook
      ansible.builtin.command: >
        ansible-playbook -i {{ workshop_repo_dir }}/inventory/hosts.ini
        {{ workshop_repo_dir }}/setup/enroll-idm-clients.yml
      environment:
        ANSIBLE_HOST_KEY_CHECKING: "False"
      tags:
        - workshop
        - ipa

    - name: Add hosts entries
      ansible.builtin.lineinfile:
        path: /etc/hosts
        line: "{{ item.ip }} {{ item.names }}"
        regexp: "^{{ item.ip }} "
        state: present
      loop:
        - { ip: "192.168.1.10", names: "control.zta.lab control aap.zta.lab" }
        - { ip: "192.168.1.11", names: "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab" }
        - { ip: "192.168.1.12", names: "vault.zta.lab vault" }
        - { ip: "192.168.1.15", names: "netbox.zta.lab netbox" }
        - { ip: "192.168.1.13", names: "wazuh.zta.lab wazuh" }
      tags:
        - network
        - hosts

    - name: Configure network connection
      community.general.nmcli:
        conn_name: "{{ interface_name }}"
        ifname: "{{ interface_name }}"
        type: ethernet
        ip4: "{{ ip_address }}"
        autoconnect: true
        state: present
      tags:
        - network

    - name: Activate network connection
      ansible.builtin.command: nmcli connection up {{ interface_name }}
      register: nmcli_up
      failed_when: false
      changed_when: nmcli_up.rc == 0
      tags:
        - network

    - name: Central node setup complete
      ansible.builtin.debug:
        msg: "✓ Central node ({{ ansible_hostname }}) setup complete"

  handlers:
    - name: Reload httpd
      ansible.builtin.systemd:
        name: httpd
        state: reloaded
      failed_when: false

    - name: Reload systemd
      ansible.builtin.systemd:
        daemon_reload: true

    - name: Start container-keycloak
      ansible.builtin.systemd:
        name: container-keycloak
        state: started
      failed_when: false

# =============================================================================
# COMPLETION
# =============================================================================
- name: Display Completion Message
  hosts: localhost
  gather_facts: false

  tasks:
    - name: Display completion banner
      ansible.builtin.debug:
        msg: |
          ============================================
          ✓ ZTA Lab Setup Complete!
          ============================================
          All nodes have been configured successfully.

          Access Points:
          - AAP Controller: https://aap.zta.lab
          - Keycloak: https://keycloak.zta.lab:8543
          - NetBox: http://netbox.zta.lab:8000
          - Vault: http://vault.zta.lab:8200
          - Wazuh: https://wazuh.zta.lab
          ============================================


EOF

ansible-galaxy install -r /tmp/requirements.yml
ansible-playbook -i /tmp/inventory /tmp/lab_setup.yml 
