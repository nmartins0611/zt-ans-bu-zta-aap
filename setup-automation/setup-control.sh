#!/bin/bash
set -euo pipefail

echo "Starting Control node setup (bootstrap phase)..."
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

###############################################################################
# 1. Validate required environment variables
###############################################################################

for var in TMM_ORG TMM_ID AH_TOKEN; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var environment variable is not set"
        exit 1
    fi
done

###############################################################################
# 2. Enable subscription-manager repo management (idempotent)
###############################################################################

CURRENT_MANAGE_REPOS=$(subscription-manager config --list | grep -oP 'manage_repos\s*=\s*\[\K[^\]]+' || echo "unknown")
if [ "$CURRENT_MANAGE_REPOS" = "1" ]; then
    echo "SKIP: manage_repos already enabled"
else
    subscription-manager config --rhsm.manage_repos=1
    subscription-manager refresh
fi

###############################################################################
# 3. Setup Ansible configuration with AH Token
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
[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
pipelining = True
EOF

###############################################################################
# 4. Install packages
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
# 5. Clone workshop repo (idempotent)
###############################################################################

if [ -d /tmp/zta-workshop-aap ]; then
    echo "SKIP: /tmp/zta-workshop-aap already exists"
else
    retry "Clone ZTA workshop repo (zta-container branch)" \
        git clone -b zta-container https://github.com/nmartins0611/zta-workshop-aap.git /tmp/zta-workshop-aap
fi

###############################################################################
# 6. Install Ansible collections
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

run_if_needed "Install Ansible collections" \
    bash -c 'ansible-galaxy collection list | grep -q "ansible.controller"' \
    -- \
    ansible-galaxy install -r /tmp/requirements.yml

cp /tmp/zta-workshop-aap/ansible.cfg /etc/ansible/

echo ""
echo "control bootstrap phase complete"
