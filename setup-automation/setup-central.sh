#!/bin/bash
set -euo pipefail
systemctl stop firewalld
setenforce 0
export ANSIBLE_HOST_KEY_CHECKING=False
wget -O /tmp/vault-ssh-helper.zip https://releases.hashicorp.com/vault-ssh-helper/0.2.1/vault-ssh-helper_0.2.1_linux_amd64.zip

 rm -rf /tmp/zta-workshop-aap

echo "Setup the AH Token for ansible"
###############################################################################
# Setup AH
###############################################################################

if [ -z "$AH_TOKEN" ]; then
    echo "Error: AH_TOKEN environment variable is not set"
    echo "Usage: AH_TOKEN='your-token-here' $0"
    exit 1
fi

# Create ~/.ansible.cfg with AH_TOKEN substituted
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


echo "Setup the Satellite links"

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
# 1. Validate required variables
###############################################################################

for var in SATELLITE_URL SATELLITE_ORG SATELLITE_ACTIVATIONKEY; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is not set"
        exit 1
    fi
done

###############################################################################
# 2. Disable tmpfiles service
###############################################################################

# if systemctl is-active --quiet systemd-tmpfiles-setup.service; then
#     systemctl stop systemd-tmpfiles-setup.service
# else
#     echo "SKIP: systemd-tmpfiles-setup already stopped"
# fi

# if systemctl is-enabled --quiet systemd-tmpfiles-setup.service 2>/dev/null; then
#     systemctl disable systemd-tmpfiles-setup.service
# else
#     echo "SKIP: systemd-tmpfiles-setup already disabled"
# fi

###############################################################################
# 3. Clean repos & subscriptions (only if not already registered)
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
# 4. Register with Satellite
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
# 5. Install packages
###############################################################################

run_if_needed "Install base packages" \
    rpm -q dnf-utils git nano \
    -- \
    dnf install -y dnf-utils git nano

run_if_needed "Install system packages" \
    rpm -q python3-libsemanage ansible-core python-requests ipa-client sssd oddjob-mkhomedir \
    -- \
    dnf install -y python3-libsemanage git ansible-core python-requests \
                   ipa-client sssd oddjob-mkhomedir

###############################################################################
# 6. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control aap.zta.lab"
ensure_hosts_entry "192.168.1.11" "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab wazuh.zta.lab gitea.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"

###############################################################################
# 7. Network configuration (idempotent)
###############################################################################
###############################################################################
# 7. Network configuration (idempotent)
###############################################################################

ensure_nmcli_connection "enp2s0" \
    type ethernet con-name enp2s0 ifname enp2s0 \
    ipv4.addresses 192.168.1.11/24 \
    ipv4.method manual \
    connection.autoconnect yes

nmcli connection up enp2s0 || true

###############################################################################
# 8. Clone workshop repo (idempotent)
###############################################################################

# if [ -d /tmp/zta-workshop-aap ]; then
#     echo "SKIP: /tmp/zta-workshop-aap already exists"
# else
#     retry "Clone ZTA workshop repo" \
#         git clone https://github.com/nmartins0611/zta-workshop-aap.git /tmp/zta-workshop-aap
        
# fi

if [ -d /tmp/zta-workshop-aap ]; then
    echo "SKIP: /tmp/zta-workshop-aap already exists"
else
    # Corrected the line below
    retry "Clone ZTA workshop repo (idm_dev branch)" \
        git clone -b zta-container https://github.com/nmartins0611/zta-workshop-aap.git /tmp/zta-workshop-aap
fi

###############################################################################
# 9. Create supporting directories and files
###############################################################################
ansible-galaxy collection install community.general
###############################################################################
# 13. IPA rewrite config (idempotent) — must run after integrate.yml
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

podman stop keycloak
systemctl stop container-keycloak
systemctl kill container-keycloak
podman rm --force keycloak
podman create --name keycloak --restart=always -p 8180:8080 -p 8543:8443 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=ansible123! -e KC_HOSTNAME=keycloak-https-${GUID}.${DOMAIN} -e KC_HTTPS_CERTIFICATE_FILE=/opt/certs/server.crt -e KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/certs/server.key -e KC_HTTP_ENABLED=true -v /opt/keycloak/certs:/opt/certs:Z registry.redhat.io/rhbk/keycloak-rhel9:24 start --hostname=keycloak-https-${GUID}.${DOMAIN} --https-port=8443 --http-enabled=true --proxy-headers forwarded
sed -i "s/^PIDFile/d/" /etc/systemd/system/container-keycloak.service
systemctl daemon-reload
systemctl start container-keycloak

rm -rf ~/.ansible.cfg

echo "✓ central setup complete"
