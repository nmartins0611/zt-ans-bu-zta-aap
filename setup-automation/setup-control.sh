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
tee /tmp/setup.yml << EOF
### Automation Controller setup
###
---
- name: Setup Controller
  hosts: localhost
  connection: local
  collections:
    - ansible.controller

  vars:
    aws_access_key: "{{ lookup('env', 'AWS_ACCESS_KEY_ID') | default('AWS_ACCESS_KEY_ID_NOT_FOUND', true) }}"
    aws_secret_key: "{{ lookup('env', 'AWS_SECRET_ACCESS_KEY') | default('AWS_SECRET_ACCESS_KEY_NOT_FOUND', true) }}"
    aws_default_region: "{{ lookup('env', 'AWS_DEFAULT_REGION') | default('AWS_DEFAULT_REGION_NOT_FOUND', true) }}"
    quay_username: "{{ lookup('env', 'QUAY_USERNAME') | default('QUAY_USERNAME_NOT_FOUND', true) }}"
    quay_password: "{{ lookup('env', 'QUAY_PASSWORD') | default('QUAY_PASSWORD_NOT_FOUND', true) }}"

  tasks:
    - name: Add AWS credential
      ansible.controller.credential:
        name: 'AWS Credential'
        organization: Default
        credential_type: "Amazon Web Services"
        controller_host: "https://localhost"
        controller_username: admin
        controller_password: ansible123!
        validate_certs: false
        inputs:
          username: "{{ aws_access_key }}"
          password: "{{ aws_secret_key }}"

    # - name: Ensure inventory exists
    #   ansible.controller.inventory:
    #     controller_host: "https://localhost"
    #     controller_username: admin
    #     controller_password: ansible123!
    #     validate_certs: false
    #     name: "AWS Inventory"
    #     organization: Default
    #     state: present
    #   register: aws_inventory_result

    # - name: Ensure AWS EC2 inventory source exists
    #   ansible.controller.inventory_source:
    #     controller_host: "https://localhost"
    #     controller_username: admin
    #     controller_password: ansible123!
    #     validate_certs: false
    #     name: "AWS EC2 Instances Source"
    #     inventory: "AWS Inventory"
    #     source: ec2
    #     credential: "AWS Credential"
    #     source_vars:
    #       regions: ["{{ aws_default_region }}"]
    #     overwrite: true
    #     overwrite_vars: true
    #     update_on_launch: true
    #     update_cache_timeout: 300
    #     state: present
    #   register: aws_inventory_source_result

    - name: Add a Container Registry Credential to automation controller
      ansible.controller.credential:
        name: Quay Registry Credential
        description: Creds to be able to access Quay
        organization: "Default"
        state: present
        credential_type: "Container Registry"
        controller_username: admin
        controller_password: ansible123!
        controller_host: "https://localhost"
        validate_certs: false
        inputs:
          username: "{{ quay_username }}"
          password: "{{ quay_password }}"
          host: "quay.io"
      register: controller_try
      retries: 10
      until: controller_try is not failed

    - name: Add EE to the controller instance
      ansible.controller.execution_environment:
        name: "Terraform Execution Environment"
        image: quay.io/acme_corp/terraform_ee
        credential: Quay Registry Credential
        controller_username: admin
        controller_password: ansible123!
        controller_host: "https://localhost"
        validate_certs: false

    - name: Add project
      ansible.controller.project:
        name: "Terraform Demos Project"
        description: "This is from the local gitea instance"
        organization: "Default"
        state: present
        scm_type: git
        scm_url: http://gitea:3000/laborg/aap-hashi-lab.git
#        scm_url: https://github.com/ansible-tmm/aap-hashi-lab.git
        default_environment: "Terraform Execution Environment"
        controller_username: admin
        controller_password: ansible123!
        controller_host: "https://localhost"
        validate_certs: false

    - name: Delete native job template
      ansible.controller.job_template:
        name: "Demo Job Template"
        state: "absent"
        controller_username: admin
        controller_password: ansible123!
        controller_host: "https://localhost"
        validate_certs: false

    - name: Add a TERRAFORM INVENTORY
      ansible.controller.inventory:
        name: "Terraform Inventory"
        description: "Our Terraform Inventory"
        organization: "Default"
        state: present
        controller_username: admin
        controller_password: ansible123!
        controller_host: "https://localhost"
        validate_certs: false
      
EOF
export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

ANSIBLE_COLLECTIONS_PATH=/root/ansible-automation-platform-containerized-setup/collections/ansible_collections ansible-playbook -i /tmp/inventory /tmp/setup.yml
