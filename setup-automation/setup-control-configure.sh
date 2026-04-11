#!/bin/bash
set -euo pipefail

echo "Starting Control node setup (configure phase)..."
export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

###############################################################################
# 1. Run AAP playbooks
###############################################################################

PLAYBOOK_DIR="/tmp/zta-workshop-aap"
cd "${PLAYBOOK_DIR}" || { echo "ERROR: Cannot cd to ${PLAYBOOK_DIR}"; exit 1; }

ansible-playbook -i inventory/hosts.ini setup/configure-aap-credentials.yml
##ansible-playbook -i inventory/hosts.ini setup/configure-aap-ldap.yml
ansible-playbook -i inventory/hosts.ini setup/configure-aap-inventory.yml
ansible-playbook -i inventory/hosts.ini setup/configure-aap-project.yml --tags ee,project,section1
ansible-playbook -i inventory/hosts.ini setup/configure-aap-inventory.yml

echo ""
echo "control configure phase complete"
