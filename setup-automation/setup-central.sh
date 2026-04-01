#!/bin/bash
set -euo pipefail

echo "Starting Central node setup..."

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
# 1. Validate required environment variables
###############################################################################

for var in AH_TOKEN TMM_ORG TMM_ID GUID DOMAIN; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var environment variable is not set"
        echo "Usage: AH_TOKEN='...' TMM_ORG='...' TMM_ID='...' GUID='...' DOMAIN='...' $0"
        exit 1
    fi
done

###############################################################################
# 2. SELinux and Firewall configuration
###############################################################################

CURRENT_MODE=$(getenforce)
if [ "${CURRENT_MODE}" = "Permissive" ] || [ "${CURRENT_MODE}" = "Disabled" ]; then
    echo "SKIP: SELinux already in ${CURRENT_MODE} mode"
else
    setenforce 0
    echo "SELinux set to Permissive"
fi

if systemctl is-active --quiet firewalld; then
    systemctl stop firewalld
    echo "Firewalld stopped"
else
    echo "SKIP: Firewalld already stopped"
fi

###############################################################################
# 3. Environment variables
###############################################################################

export ANSIBLE_HOST_KEY_CHECKING=False
export NETBOX_TOKEN=0123456789abcdef0123456789abcdef01234567

###############################################################################
# 4. Clean temp directory
###############################################################################

rm -rf /tmp/zta-workshop-aap

###############################################################################
# 5. Setup Ansible configuration with AH Token
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
#token=""
[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
pipelining = True
EOF

###############################################################################
# 6. Register with subscription manager (idempotent)
###############################################################################

if subscription-manager identity &>/dev/null; then
    echo "SKIP: Already registered – skipping registration"
else
    echo "Cleaning existing subscription data..."
    dnf clean all || true
    rm -f /etc/yum.repos.d/redhat-rhui*.repo
    sed -i 's/enabled=1/enabled=0/' /etc/dnf/plugins/amazon-id.conf 2>/dev/null || true
    subscription-manager unregister 2>/dev/null || true
    subscription-manager remove --all 2>/dev/null || true
    subscription-manager clean

    echo "Registering with subscription manager..."
    if subscription-manager register --org="$TMM_ORG" --activationkey="$TMM_ID" --force; then
        echo "System registered successfully!"
    else
        echo "Registration failed. Please check your credentials and network connection."
        exit 1
    fi
fi

###############################################################################
# 7. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control aap.zta.lab"
ensure_hosts_entry "192.168.1.11" "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"
ensure_hosts_entry "192.168.1.13" "wazuh.zta.lab wazuh"

###############################################################################
# 8. Install packages
###############################################################################

run_if_needed "Install base packages" \
    rpm -q dnf-utils \
    -- \
    dnf install -y dnf-utils git nano

run_if_needed "Install system packages" \
    rpm -q python3-libsemanage \
    -- \
    dnf install -y python3-libsemanage ansible-core python3-requests \
                   ipa-client sssd oddjob-mkhomedir python3-pip

run_if_needed "Install pynetbox" \
    python3 -c "import pynetbox" \
    -- \
    pip3 install pynetbox

###############################################################################
# 9. Download IPA RPMs for containers
###############################################################################

if [ ! -d /tmp/ipa-rpms ]; then
    mkdir -p /tmp/ipa-rpms
    dnf download --resolve --destdir /tmp/ipa-rpms ipa-client
fi

for c in app db; do
    if podman container exists "$c" 2>/dev/null; then
        if podman exec "$c" rpm -q ipa-client &>/dev/null; then
            echo "SKIP: ipa-client already installed in container '$c'"
        else
            podman cp /tmp/ipa-rpms "$c":/tmp/ipa-rpms
            podman exec "$c" bash -c 'dnf install -y /tmp/ipa-rpms/*.rpm && rm -rf /tmp/ipa-rpms'
        fi
    else
        echo "SKIP: Container '$c' does not exist"
    fi
done

###############################################################################
# 10. Clone workshop repo (idempotent)
###############################################################################

if [ -d /tmp/zta-workshop-aap ]; then
    echo "SKIP: /tmp/zta-workshop-aap already exists"
else
    retry "Clone ZTA workshop repo (zta-container branch)" \
        git clone -b zta-container https://github.com/nmartins0611/zta-workshop-aap.git /tmp/zta-workshop-aap
fi

###############################################################################
# 11. Install Ansible collections
###############################################################################

run_if_needed "Install community.general collection" \
    ansible-galaxy collection list | grep -q "community.general" \
    -- \
    ansible-galaxy collection install community.general

run_if_needed "Install netbox.netbox collection" \
    ansible-galaxy collection list | grep -q "netbox.netbox" \
    -- \
    ansible-galaxy collection install netbox.netbox

run_if_needed "Install ansible.controller collection" \
    ansible-galaxy collection list | grep -q "ansible.controller" \
    -- \
    ansible-galaxy collection install ansible.controller

###############################################################################
# 12. IPA rewrite config (idempotent)
###############################################################################

IPA_REWRITE="/etc/httpd/conf.d/ipa-rewrite.conf"
if grep -q "RequestHeader set Host central.zta.lab" "$IPA_REWRITE" 2>/dev/null; then
    echo "SKIP: ipa-rewrite.conf already configured"
else
    tee "$IPA_REWRITE" << 'IPA'
# VERSION 7 - DO NOT REMOVE THIS LINE
RequestHeader set Host central.zta.lab
RequestHeader set Referer https://central.zta.lab/ipa/ui/
RewriteEngine on
RewriteRule ^/ipa/ui/js/freeipa/plugins.js$    /ipa/wsgi/plugins.py [PT]
RewriteCond %{HTTP_HOST}    ^ipa-ca.example.local$ [NC]
RewriteCond %{REQUEST_URI}  !^/ipa/crl
RewriteCond %{REQUEST_URI}  !^/(ca|kra|pki|acme)
IPA

    if systemctl is-active --quiet httpd; then
        systemctl reload httpd
        echo "Apache httpd reloaded"
    else
        echo "NOTE: httpd not running, config will apply when started"
    fi
fi

###############################################################################
# 13. Reconfigure Keycloak container
###############################################################################

echo "Reconfiguring Keycloak container..."
podman stop keycloak 2>/dev/null || true
systemctl stop container-keycloak 2>/dev/null || true
systemctl kill container-keycloak 2>/dev/null || true
podman rm --force keycloak 2>/dev/null || true

podman create --name keycloak --restart=always \
    -p 8180:8080 -p 8543:8443 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=ansible123! \
    -e KC_HOSTNAME=keycloak-https-${GUID}.${DOMAIN} \
    -e KC_HTTPS_CERTIFICATE_FILE=/opt/certs/server.crt \
    -e KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/certs/server.key \
    -e KC_HTTP_ENABLED=true \
    -v /opt/keycloak/certs:/opt/certs:Z \
    registry.redhat.io/rhbk/keycloak-rhel9:24 start \
    --hostname=keycloak-https-${GUID}.${DOMAIN} \
    --https-port=8443 \
    --http-enabled=true \
    --proxy-headers forwarded

if [ -f /etc/systemd/system/container-keycloak.service ]; then
    sed -i "/^PIDFile/d" /etc/systemd/system/container-keycloak.service
    systemctl daemon-reload
fi
systemctl start container-keycloak

###############################################################################
# 14. Network configuration (idempotent)
###############################################################################

echo "Configuring network interface..."
ensure_nmcli_connection "enp2s0" \
    type ethernet con-name enp2s0 ifname enp2s0 \
    ipv4.addresses 192.168.1.11/24 \
    ipv4.method manual \
    connection.autoconnect yes

nmcli connection up enp2s0 || true

###############################################################################
# 15. Run Ansible playbooks
###############################################################################

echo "Running Ansible playbooks..."
ansible-playbook -i /tmp/zta-workshop-aap/inventory/hosts.ini /tmp/zta-workshop-aap/setup/configure-dns.yml
ansible-playbook -i /tmp/zta-workshop-aap/inventory/hosts.ini /tmp/zta-workshop-aap/setup/configure-vault.yml
ansible-playbook -i /tmp/zta-workshop-aap/inventory/hosts.ini /tmp/zta-workshop-aap/setup/configure-vault-ssh.yml
ansible-playbook -i /tmp/zta-workshop-aap/inventory/hosts.ini /tmp/zta-workshop-aap/setup/enroll-idm-clients.yml

###############################################################################
# 16. Cleanup
###############################################################################

echo "Cleaning up temporary ansible configuration..."
rm -rf ~/.ansible.cfg

echo ""
echo "✓ central setup complete"
