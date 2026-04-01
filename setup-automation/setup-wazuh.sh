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
# 1. Validate Environment
###############################################################################

for var in TMM_ORG TMM_ID; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is not set. Please export it before running."
        exit 1
    fi
done

###############################################################################
# 2. Subscription Management (Direct Registration)
###############################################################################

if subscription-manager identity &>/dev/null; then
    echo "SKIP: System already registered."
else
    echo "Cleaning existing subscription data..."
    subscription-manager clean

    echo "Registering system with Org ID: ${TMM_ORG}..."
    subscription-manager register --org="$TMM_ORG" --activationkey="$TMM_ID" --force
    
    echo "Enabling repo management..."
    subscription-manager config --rhsm.manage_repos=1
    subscription-manager refresh
fi

###############################################################################
# 3. Network configuration (idempotent)
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
# 4. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control aap.zta.lab"
ensure_hosts_entry "192.168.1.11" "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"
ensure_hosts_entry "192.168.1.13" "wazuh.zta.lab wazuh"

###############################################################################
# 5. Install packages
###############################################################################

run_if_needed "Install required system packages" \
    rpm -q python3-libsemanage \
    -- \
    dnf install -y python3-libsemanage ansible-core git podman

###############################################################################
# 6. Wazuh deployment playbook (COMMENTED OUT)
###############################################################################

# echo "[wazuh]" > /tmp/wazuh_inventory
# echo "localhost ansible_connection=local" >> /tmp/wazuh_inventory

# tee /tmp/waz-setup.yml << 'EOF'
# ---
# - name: Wazuh All-in-One Deployment with SOC Analyst User
#   hosts: wazuh
#   become: true
#   gather_facts: true
#   vars:
#     wazuh_version: "4.10"
#     soc_user: "soc-analyst"
#     soc_password: "ansible123!"
#     wazuh_install_script: "https://packages.wazuh.com/{{ wazuh_version }}/wazuh-install.sh"
#   tasks:
#     - name: Download Wazuh installation assistant
#       ansible.builtin.get_url:
#         url: "{{ wazuh_install_script }}"
#         dest: /root/wazuh-install.sh
#         mode: "0755"
#     - name: Run Wazuh all-in-one installation
#       ansible.builtin.command:
#         cmd: bash /root/wazuh-install.sh -a
#         creates: /var/ossec/bin/wazuh-control
# EOF

# ansible-playbook -i /tmp/wazuh_inventory /tmp/waz-setup.yml

###############################################################################
# 7. Cleanup
###############################################################################

export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

rm -f ~/.ansible.cfg

echo "✓ infrastructure setup complete (Wazuh playbook skipped)"
