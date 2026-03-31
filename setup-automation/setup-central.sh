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
# 1. Validate required variables
###############################################################################

for var in AH_TOKEN SATELLITE_URL SATELLITE_ORG SATELLITE_ACTIVATIONKEY GUID DOMAIN; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is not set"
        exit 1
    fi
done

###############################################################################
# 2. Early system hardening
###############################################################################

export ANSIBLE_HOST_KEY_CHECKING=False
export NETBOX_TOKEN="${NETBOX_TOKEN:-0123456789abcdef0123456789abcdef01234567}"

systemctl is-active --quiet firewalld && systemctl stop firewalld || true
getenforce 2>/dev/null | grep -qi enforcing && setenforce 0 || true

rm -rf /tmp/zta-workshop-aap

###############################################################################
# 3. Temporary ansible.cfg for galaxy installs (auto-cleaned on exit)
###############################################################################

ANSIBLE_TMP_CFG="$(mktemp /tmp/ansible-cfg.XXXXXX)"
trap 'rm -f "$ANSIBLE_TMP_CFG"' EXIT
export ANSIBLE_CONFIG="$ANSIBLE_TMP_CFG"

tee "$ANSIBLE_TMP_CFG" > /dev/null <<EOF
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
# 4. Clean repos & subscriptions (only if not already registered)
###############################################################################

if subscription-manager identity &>/dev/null; then
    echo "SKIP: Already registered with Satellite – skipping clean/unregister"
else
    echo "Cleaning existing repos and subscriptions..."
    dnf clean all || true
    rm -f /etc/yum.repos.d/redhat-rhui*.repo
    sed -i 's/enabled=1/enabled=0/' /etc/dnf/plugins/amazon-id.conf 2>/dev/null || true
    subscription-manager unregister 2>/dev/null || true
    subscription-manager remove --all 2>/dev/null || true
    subscription-manager clean

    OLD_KATELLO=$(rpm -qa | grep katello-ca-consumer || true)
    if [ -n "$OLD_KATELLO" ]; then
        rpm -e "$OLD_KATELLO" 2>/dev/null || true
    fi
fi

###############################################################################
# 5. Register with Satellite
###############################################################################

CA_CERT="/etc/pki/ca-trust/source/anchors/${SATELLITE_URL}.ca.crt"

run_if_needed "Download Katello CA cert" \
    test -f "${CA_CERT}" \
    -- \
    curl -fsSkL \
        "https://${SATELLITE_URL}/pub/katello-server-ca.crt" \
        -o "${CA_CERT}"

retry "Update CA trust" \
    update-ca-trust extract

run_if_needed "Install Katello consumer RPM" \
    rpm -q katello-ca-consumer \
    -- \
    rpm -Uhv --force "https://${SATELLITE_URL}/pub/katello-ca-consumer-latest.noarch.rpm"

run_if_needed "Register with Satellite" \
    subscription-manager identity \
    -- \
    subscription-manager register \
        --org="${SATELLITE_ORG}" \
        --activationkey="${SATELLITE_ACTIVATIONKEY}"

retry "Refresh subscription" \
    subscription-manager refresh

###############################################################################
# 6. Install packages
###############################################################################

run_if_needed "Install base packages" \
    rpm -q dnf-utils git nano \
    -- \
    dnf install -y dnf-utils git nano

run_if_needed "Install system packages" \
    rpm -q python3-libsemanage ansible-core python-requests ipa-client sssd oddjob-mkhomedir python-pip unzip \
    -- \
    dnf install -y python3-libsemanage git ansible-core python-requests \
                   ipa-client sssd oddjob-mkhomedir python-pip unzip

python3 -c "import flask" 2>/dev/null || {
    pip download flask -d /tmp/flask-wheels
    pip install --no-index --find-links /tmp/flask-wheels flask --user
}

python3 -c "import pynetbox" 2>/dev/null || pip install pynetbox --user

###############################################################################
# 7. Install IPA client into app/db containers
###############################################################################

if [ ! -d /tmp/ipa-rpms ]; then
    mkdir -p /tmp/ipa-rpms
    dnf download --resolve --destdir /tmp/ipa-rpms ipa-client
fi

for c in app db; do
    if podman exec "$c" rpm -q ipa-client &>/dev/null; then
        echo "SKIP: ipa-client already installed in container '$c'"
    else
        podman cp /tmp/ipa-rpms "$c":/tmp/ipa-rpms
        podman exec "$c" bash -c 'dnf install -y /tmp/ipa-rpms/*.rpm && rm -rf /tmp/ipa-rpms'
    fi
done

###############################################################################
# 8. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control aap.zta.lab"
ensure_hosts_entry "192.168.1.11" "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"
ensure_hosts_entry "192.168.1.13" "wazuh.zta.lab wazuh"

###############################################################################
# 9. Network configuration (idempotent)
###############################################################################

ensure_nmcli_connection "enp2s0" \
    type ethernet con-name enp2s0 ifname enp2s0 \
    ipv4.addresses 192.168.1.11/24 \
    ipv4.method manual \
    connection.autoconnect yes

nmcli connection up enp2s0 || true

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

ansible-galaxy collection install community.general netbox.netbox ansible.controller

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
    systemctl reload httpd
fi

###############################################################################
# 13. Keycloak container (idempotent)
###############################################################################

KEYCLOAK_IMAGE="registry.redhat.io/rhbk/keycloak-rhel9:24"
KC_HOSTNAME="keycloak-https-${GUID}.${DOMAIN}"

if podman inspect keycloak &>/dev/null; then
    echo "SKIP: keycloak container already exists"
else
    podman create --name keycloak --restart=always \
        -p 8180:8080 -p 8543:8443 \
        -e KEYCLOAK_ADMIN=admin \
        -e KEYCLOAK_ADMIN_PASSWORD=ansible123! \
        -e KC_HOSTNAME="${KC_HOSTNAME}" \
        -e KC_HTTPS_CERTIFICATE_FILE=/opt/certs/server.crt \
        -e KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/certs/server.key \
        -e KC_HTTP_ENABLED=true \
        -v /opt/keycloak/certs:/opt/certs:Z \
        "${KEYCLOAK_IMAGE}" start \
        --hostname="${KC_HOSTNAME}" \
        --https-port=8443 \
        --http-enabled=true \
        --proxy-headers forwarded

    sed -i "/^PIDFile/d" /etc/systemd/system/container-keycloak.service
    systemctl daemon-reload
fi

systemctl start container-keycloak || true

###############################################################################
# 14. Run post-setup playbooks
###############################################################################

REPO_DIR="/tmp/zta-workshop-aap"
INVENTORY="${REPO_DIR}/inventory/hosts.ini"
PLAYBOOK_DIR="${REPO_DIR}/setup"
PLAYBOOKS=(
    "${PLAYBOOK_DIR}/configure-dns.yml"
    "${PLAYBOOK_DIR}/configure-vault.yml"
    "${PLAYBOOK_DIR}/configure-vault-ssh.yml"
    "${PLAYBOOK_DIR}/enroll-idm-clients.yml"
)   

for pb in "${PLAYBOOKS[@]}"; do
    if [ ! -f "$pb" ]; then
        echo "ERROR: Playbook not found: $pb"
        exit 1
    fi
    echo "Running playbook: $pb"
    ansible-playbook -i "$INVENTORY" "$pb"
done

echo "central setup complete"
