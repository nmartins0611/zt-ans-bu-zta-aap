#!/bin/bash
set -euo pipefail

###############################################################################
# Retry helper
###############################################################################
retry() {
    local desc="$1"
    shift
    local max_attempts=3
    local delay=5

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

###############################################################################
# Validate required variables
###############################################################################
for var in SATELLITE_URL SATELLITE_ORG SATELLITE_ACTIVATIONKEY; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is not set"
        exit 1
    fi
done

###############################################################################
# Clean up subscriptions
###############################################################################
dnf clean all || true
subscription-manager unregister 2>/dev/null || true
subscription-manager remove --all 2>/dev/null || true
subscription-manager clean

# Remove old Katello consumer RPM if present
OLD_KATELLO=$(rpm -qa | grep katello-ca-consumer || true)
if [ -n "$OLD_KATELLO" ]; then
    rpm -e "$OLD_KATELLO"
fi

###############################################################################
# Register with Satellite
###############################################################################
retry "Download Katello CA cert" \
    curl -sS -k -L \
    "https://${SATELLITE_URL}/pub/katello-server-ca.crt" \
    -o "/etc/pki/ca-trust/source/anchors/${SATELLITE_URL}.ca.crt"

retry "Update CA trust" \
    update-ca-trust extract

retry "Install Katello consumer RPM" \
    rpm -Uhv --force "https://${SATELLITE_URL}/pub/katello-ca-consumer-latest.noarch.rpm"

retry "Register with Satellite" \
    subscription-manager register \
    --org="${SATELLITE_ORG}" \
    --activationkey="${SATELLITE_ACTIVATIONKEY}"

retry "Refresh subscription" \
    subscription-manager refresh

###############################################################################
# Install packages
###############################################################################
retry "Install base packages" \
    dnf install -y dnf-utils git nano

retry "Add Docker repo" \
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

retry "Install IPA client packages" \
    dnf install -y ipa-client sssd oddjob-mkhomedir

retry "Install Python3 libraries" \
    dnf install -y python3-pip python3-libsemanage

###############################################################################
# SELinux
###############################################################################
setenforce 0

###############################################################################
# /etc/hosts
###############################################################################
cat >> /etc/hosts <<EOF
192.168.1.10 control.zta.lab control
192.168.1.11 central.zta.lab keycloak.zta.lab opa.zta.lab
192.168.1.12 vault.zta.lab vault
192.168.1.13 wazuh.zta.lab wazuh
192.168.1.14 node01.zta.lab node01
192.168.1.15 netbox.zta.lab netbox
EOF

###############################################################################
# Network configuration
###############################################################################
nmcli connection add type ethernet con-name eth1 ifname eth1 \
    ipv4.addresses 192.168.1.10/24 \
    ipv4.method manual \
    ipv4.dns 192.168.1.11 \
    ipv4.dns-search zta.lab \
    connection.autoconnect yes

nmcli connection up eth1

# Create a playbook for the user to execute
tee /tmp/setup.yml << EOF
# ### Automation Controller setup
# ###
# ---
# - name: Setup Controller
#   hosts: localhost
#   connection: local
#   collections:
#     - ansible.controller

#   vars:
#     aws_access_key: "{{ lookup('env', 'AWS_ACCESS_KEY_ID') | default('AWS_ACCESS_KEY_ID_NOT_FOUND', true) }}"
#     aws_secret_key: "{{ lookup('env', 'AWS_SECRET_ACCESS_KEY') | default('AWS_SECRET_ACCESS_KEY_NOT_FOUND', true) }}"
#     aws_default_region: "{{ lookup('env', 'AWS_DEFAULT_REGION') | default('AWS_DEFAULT_REGION_NOT_FOUND', true) }}"
#     quay_username: "{{ lookup('env', 'QUAY_USERNAME') | default('QUAY_USERNAME_NOT_FOUND', true) }}"
#     quay_password: "{{ lookup('env', 'QUAY_PASSWORD') | default('QUAY_PASSWORD_NOT_FOUND', true) }}"
#     ssh_private_key: "{{ lookup('env', 'SSH_KEY') | default('SSH_KEY_NOT_FOUND', true) }}"

#   tasks:
#     - name: Add AWS credential
#       ansible.controller.credential:
#         name: 'AWS Credential'
#         organization: Default
#         credential_type: "Amazon Web Services"
#         controller_host: "https://localhost"
#         controller_username: admin
#         controller_password: ansible123!
#         validate_certs: false
#         inputs:
#           username: "{{ aws_access_key }}"
#           password: "{{ aws_secret_key }}"

#     - name: Add SSH Private Key credential
#       ansible.controller.credential:
#         name: 'SSH Credentials'
#         description: Creds to SSH to the inventory RHEL hosts
#         organization: "Default"
#         state: present
#         credential_type: "Machine"
#         controller_username: admin
#         controller_password: ansible123!
#         controller_host: "https://localhost"
#         validate_certs: false
#         inputs:
#           username: ec2-user
#           ssh_key_data: "{{ ssh_private_key }}"
#       register: controller_try
#       retries: 10
#       until: controller_try is not failed

#     - name: Add a Container Registry Credential to automation controller
#       ansible.controller.credential:
#         name: Quay Registry Credential
#         description: Creds to be able to access Quay
#         organization: "Default"
#         state: present
#         credential_type: "Container Registry"
#         controller_username: admin
#         controller_password: ansible123!
#         controller_host: "https://localhost"
#         validate_certs: false
#         inputs:
#           username: "{{ quay_username }}"
#           password: "{{ quay_password }}"
#           host: "quay.io"
#       register: controller_try
#       retries: 10
#       until: controller_try is not failed

#     - name: Add EE to the controller instance
#       ansible.controller.execution_environment:
#         name: "Terraform Execution Environment"
#         image: quay.io/acme_corp/terraform_ee
#         credential: Quay Registry Credential
#         controller_username: admin
#         controller_password: ansible123!
#         controller_host: "https://localhost"
#         validate_certs: false

#     - name: Add project
#       ansible.controller.project:
#         name: "Terraform Demos Project"
#         description: "This is from the GitHub repository for this labs content"
#         organization: "Default"
#         state: present
#         scm_type: git
#         scm_url: https://github.com/ansible-tmm/aap-hashi-lab.git
#         default_environment: "Terraform Execution Environment"
#         controller_username: admin
#         controller_password: ansible123!
#         controller_host: "https://localhost"
#         validate_certs: false

#     - name: Delete native job template
#       ansible.controller.job_template:
#         name: "Demo Job Template"
#         state: "absent"
#         controller_username: admin
#         controller_password: ansible123!
#         controller_host: "https://localhost"
#         validate_certs: false

#     - name: Add a TERRAFORM INVENTORY
#       ansible.controller.inventory:
#         name: "Terraform Inventory"
#         description: "Our Terraform Inventory"
#         organization: "Default"
#         state: present
#         controller_username: admin
#         controller_password: ansible123!
#         controller_host: "https://localhost"
#         validate_certs: false

#     - name: Installs Nginx on the RHEL hosts
#       ansible.controller.job_template:
#         name: "Install Nginx on RHEL"
#         description: "Install Nginx on RHEL"
#         job_type: "run"
#         organization: "Default"
#         state: present
#         inventory: "Terraform Inventory"
#         project: "Terraform Demos Project"
#         playbook: "playbooks/install_nginx-rhel.yml"
#         credentials:
#           - "SSH Credentials"
#         controller_username: admin
#         controller_password: ansible123!
#         controller_host: "https://localhost"
#         validate_certs: false

# EOF
# export ANSIBLE_LOCALHOST_WARNING=False
# export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

# ANSIBLE_COLLECTIONS_PATH=/root/ansible-automation-platform-containerized-setup/collections/ansible_collections ansible-playbook -i /tmp/inventory /tmp/setup.yml

git clone https://github.com/nmartins0611/zta-aap-workshop.git /tmp/
