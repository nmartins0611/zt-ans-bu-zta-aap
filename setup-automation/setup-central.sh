#!/bin/bash
set -euo pipefail

echo "Starting Central node setup (bootstrap phase)..."

cleanup() {
    echo "Cleaning up temporary ansible configuration..."
    rm -rf ~/.ansible.cfg
}
trap cleanup EXIT

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

for var in AH_TOKEN TMM_ORG TMM_ID GUID DOMAIN; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var environment variable is not set"
        echo "Usage: AH_TOKEN='...' TMM_ORG='...' TMM_ID='...' GUID='...' DOMAIN='...' $0"
        exit 1
    fi
done

###############################################################################
# 2. Environment variables
###############################################################################

export ANSIBLE_HOST_KEY_CHECKING=False
export NETBOX_TOKEN=0123456789abcdef0123456789abcdef01234567
export ANSIBLE_CONFIG=/tmp/zta-workshop-aap/ansible.cfg
mkdir -p /root/.ansible/cp

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

run_if_needed "Install pynetbox" \
    python3 -c "import pynetbox" \
    -- \
     pip3 install pynetbox --user

run_if_needed "Install paramiko" \
    python3 -c "import paramiko" \
    -- \
     pip3 install paramiko --user

###############################################################################
# 5. Download IPA RPMs for containers
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
# 6. Clone workshop repo (idempotent)
###############################################################################

if [ -d /tmp/zta-workshop-aap ]; then
    echo "SKIP: /tmp/zta-workshop-aap already exists"
else
    retry "Clone ZTA workshop repo (zta-container branch)" \
        git clone -b zta-container https://github.com/nmartins0611/zta-workshop-aap.git /tmp/zta-workshop-aap
fi

###############################################################################
# 7. IPA rewrite config (idempotent)
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
# 8. Reconfigure Keycloak container
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
# 9. Copy ansible.cfg and run independent playbooks
###############################################################################

cp /tmp/zta-workshop-aap/ansible.cfg /etc/ansible/

PLAYBOOK_DIR="/tmp/zta-workshop-aap"
cd "${PLAYBOOK_DIR}" || { echo "ERROR: Cannot cd to ${PLAYBOOK_DIR}"; exit 1; }
ansible-playbook -i inventory/hosts.ini setup/configure-dns.yml
ansible-playbook -i inventory/hosts.ini setup/enroll-idm-clients.yml
ansible-playbook -i inventory/hosts.ini setup/deploy-central.yml --skip-tags keycloak
ansible-playbook -i inventory/hosts.ini setup/deploy-db-app.yml

echo ""
echo "central bootstrap phase complete"
