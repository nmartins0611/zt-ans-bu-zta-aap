#!/bin/bash

rm -f /etc/yum.repos.d/*.repo
sudo dnf clean all
sudo subscription-manager remove --all
sudo subscription-manager clean

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
KATELLO_INSTALLED=$(rpm -qa | grep -c katello)
if [ $KATELLO_INSTALLED -eq 0 ]; then
  retry "rpm -Uhv https://${SATELLITE_URL}/pub/katello-ca-consumer-latest.noarch.rpm"
fi
subscription-manager status
if [ $? -ne 0 ]; then
    retry "subscription-manager register --org=${SATELLITE_ORG} --activationkey=${SATELLITE_ACTIVATIONKEY}"
fi

setenforce 0

echo "%rhel ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/rhel_sudoers
chmod 440 /etc/sudoers.d/rhel_sudoers
sudo -u rhel mkdir -p /home/rhel/.ssh
sudo -u rhel chmod 700 /home/rhel/.ssh

if [ -f /home/rhel/.ssh/id_rsa ]; then
    echo "SSH key already exists. Removing old key..."
    sudo -u rhel rm -f /home/rhel/.ssh/id_rsa /home/rhel/.ssh/id_rsa.pub
fi

sudo -u rhel ssh-keygen -t rsa -b 4096 -C "rhel@$(hostname)" -f /home/rhel/.ssh/id_rsa -N ""
sudo -u rhel chmod 600 /home/rhel/.ssh/id_rsa*

systemctl stop firewalld
systemctl stop code-server
mv /home/rhel/.config/code-server/config.yaml /home/rhel/.config/code-server/config.bk.yaml

tee /home/rhel/.config/code-server/config.yaml << EOF
bind-addr: 0.0.0.0:8080
auth: none
cert: false
EOF

tee /etc/systemd/system/code-server@rhel.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/usr/bin/code-server /home/rhel/lab_exercises
EOF

systemctl daemon-reload
systemctl start code-server
dnf install unzip nano git podman -y 

## Configure sudoers for rhel user
echo "%rhel ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/rhel_sudoers
chmod 440 /etc/sudoers.d/rhel_sudoers

# Setup rhel user
cp -a /root/.ssh/* /home/rhel/.ssh/.
chown -R rhel:rhel /home/rhel/.ssh
mkdir -p /home/rhel/lab_exercises

#
chown -R rhel:rhel /home/rhel/lab_exercises/
chmod -R 777 /home/rhel/lab_exercises/

curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -o awscliv2.zip
sudo ./aws/install
#
yum install -y dnf
dnf config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
yum install terraform -y
#
#
# Delete the AWS CLI zip - clean up
FILE="/home/rhel/awscliv2.zip"
if [ -f "$FILE" ]; then
  echo "File exists, deleting: $FILE"
  rm -f "$FILE"
else
  echo "File does not exist: $FILE"
fi

#
# Create directory if it doesn't exist
mkdir -p /home/rhel/.aws
# Create the credentials file
cat > /home/rhel/.aws/credentials << EOF
[default]
aws_access_key_id = $AWS_ACCESS_KEY_ID
aws_secret_access_key = $AWS_SECRET_ACCESS_KEY
EOF

#
# Delete the test directory - clean up
DIR="/home/rhel/test"
if [ -d "$DIR" ]; then
  echo "Directory exists, deleting: $DIR"
  rm -rf "$DIR"
else
  echo "Directory does not exist: $DIR"
fi

#
# Set proper ownership and permissions
chown rhel:rhel /home/rhel/.aws/credentials
chmod 600 /home/rhel/.aws/credentials

cat > /home/rhel/.aws/config << EOF
[default]
region = $AWS_DEFAULT_REGION
EOF

# Set proper ownership and permissions
chown rhel:rhel /home/rhel/.aws/config
chmod 600 /home/rhel/.aws/config

#
#Create the DEFAULT AWS VPC
su - rhel -c "aws ec2 create-default-vpc --region $AWS_DEFAULT_REGION"
#
#
#Create the S3 bucket for the users of this AAP / Terraform lab
# Variables
BUCKET_PREFIX="aap-tf-bucket"  # Change this to your desired bucket prefix
RANDOM_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')  # Generate a random UUID and convert to lowercase
BUCKET_NAME="${BUCKET_PREFIX}-${RANDOM_ID}"
AWS_REGION="$AWS_DEFAULT_REGION"  # Change this to your desired AWS region
#
#
# Create the S3 STORAGE BUCKET NEEDED BY THE AAP 2.X CHALLENGE
echo "Creating S3 bucket: $BUCKET_NAME in region $AWS_DEFAULT_REGION"
su - rhel -c "aws s3api create-bucket --bucket $BUCKET_NAME --region $AWS_DEFAULT_REGION"
#
########
## install python3 libraries needed for the Cloud Report
dnf install -y python3-pip python3-libsemanage
#
#########
sudo dnf install python3.9 -y
sudo dnf remove python3 -y
sudo dnf upgrade crun -y
python3 --version
pip3 install --upgrade ansible-builder
#
#
mkdir -p /home/rhel/hashicorp-ee
touch /home/rhel/hashicorp-ee/execution-environment.yml
touch /home/rhel/hashicorp-ee/requirements.yml
#
#
#Enable linger for the user `rhel`
loginctl enable-linger rhel
#
#
RUNAS="sudo -u rhel"
cd /tmp || exit 1
#Runs bash with commands in the here-document as the `rhel` user
$RUNAS bash<<'EOF'
podman login --username $REG_USER --password $REG_PASS registry.redhat.io
podman pull registry.redhat.io/ansible-automation-platform-26/ee-minimal-rhel9:latest
loginctl enable-linger rhel
EOF
#
chown -R rhel:rhel /home/rhel/
chmod -R 777 /home/rhel/
chmod -R 600 /home/rhel/.ssh/*
chmod -R 600 /home/rhel/.aws/*
#
cd /home/rhel/lab_exercises
#
