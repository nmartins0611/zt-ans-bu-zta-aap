#!/bin/bash

systemctl stop systemd-tmpfiles-setup.service
systemctl disable systemd-tmpfiles-setup.service

rm -rf /etc/yum.repos.d/*
yum clean all
subscription-manager clean

retry() {
    for i in {1..3}; do
        echo "Attempt $i: $2"
        if $1; then
            return 0
        fi
        [ $i -lt 3 ] && sleep 5
    done
    echo "Failed after 3 attempts: $2"
    exit 1
}

retry "curl -k -L https://${SATELLITE_URL}/pub/katello-server-ca.crt -o /etc/pki/ca-trust/source/anchors/${SATELLITE_URL}.ca.crt"
retry "update-ca-trust"
retry "rpm -Uhv --force https://${SATELLITE_URL}/pub/katello-ca-consumer-latest.noarch.rpm"
retry "subscription-manager register --org=${SATELLITE_ORG} --activationkey=${SATELLITE_ACTIVATIONKEY}  --force"
retry "dnf install -y dnf-utils git nano"
retry "dnf install -y python3-pip python3-libsemanage git ansible-core python-requests ipa-client sssd oddjob-mkhomedir postgresql-server postgresql python3-psycopg2 python3-flask"
setenforce 0


echo "192.168.1.10 control.zta.lab control" >> /etc/hosts
echo "192.168.1.11 central.zta.lab  keycloak.zta.lab  opa.zta.lab" >> /etc/hosts
echo "192.168.1.12 vault.zta.lab vault" >> /etc/hosts
echo "192.168.1.13 wazuh.zta.lab wazuh" >> /etc/hosts
echo "192.168.1.14 node01.zta.lab node01" >> /etc/hosts
echo "192.168.1.15 netbox.zta.lab netbox" >> /etc/hosts

nmcli connection add type ethernet con-name eth1 ifname eth1 ipv4.addresses 192.168.1.14/24 ipv4.method manual connection.autoconnect yes
nmcli connection up eth1
nmcli con mod eth1 ipv4.dns 192.168.1.11
nmcli con mod eth1 ipv4.dns-search zta.lab
nmcli con up eth1



