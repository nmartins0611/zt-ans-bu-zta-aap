#!/bin/bash
set -euo pipefail

echo "Starting Central node setup (configure phase)..."

export ANSIBLE_HOST_KEY_CHECKING=False
export NETBOX_TOKEN=0123456789abcdef0123456789abcdef01234567
export ANSIBLE_CONFIG=/tmp/zta-workshop-aap/ansible.cfg

###############################################################################
# Run service-dependent playbooks
###############################################################################

PLAYBOOK_DIR="/tmp/zta-workshop-aap"
cd "${PLAYBOOK_DIR}" || { echo "ERROR: Cannot cd to ${PLAYBOOK_DIR}"; exit 1; }

ansible-playbook -i inventory/hosts.ini setup/configure-vault.yml
ansible-playbook -i inventory/hosts.ini setup/configure-vault-ssh.yml
ansible-playbook -i inventory/hosts.ini setup/configure-netbox.yml
ansible-playbook -i inventory/hosts.ini setup/integrate-splunk.yml --skip-tags arista_syslog,wazuh_splunk
ansible-playbook -i inventory/hosts.ini setup/configure-aap-podman-gateway-prereqs.yml

echo ""
echo "central configure phase complete"
