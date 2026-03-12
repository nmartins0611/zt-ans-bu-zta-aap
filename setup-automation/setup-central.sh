#!/bin/bash

systemctl stop systemd-tmpfiles-setup.service
systemctl disable systemd-tmpfiles-setup.service

echo "192.168.1.10 control.zta.lab control" >> /etc/hosts
echo "192.168.1.11  central.zta.lab  keycloak.zta.lab  opa.zta.lab" >> /etc/hosts
echo "192.168.1.12 vault.zta.lab vault" >> /etc/hosts
echo "192.168.1.13 wazuh.zta.lab wazuh" >> /etc/hosts
echo "192.168.1.14 node01.zta.lab node01" >> /etc/hosts

nmcli connection add type ethernet con-name eth1 ifname eth1 ipv4.addresses 192.168.1.11/24 ipv4.method manual connection.autoconnect yes
nmcli connection up eth1


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
dnf install -y python3-pip python3-libsemanage git ansible-core


---
- name: Verify ZTA Lab services on central.zta.lab
  hosts: all
  become: true
  gather_facts: true

  tasks:

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

