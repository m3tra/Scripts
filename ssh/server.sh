#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "$0 requires sudo."
	exit 2
fi

################
# Installation #
################

apt install ssh -y

mv -f /etc/sshd_config /etc/sshd_config.bak

echo "\
Protocol 2 \
AllowUsers user \
\
Port 22 \
\
PermitRootLogin no \
MaxAuthTries 3 \
MaxSessions 5 \
\
PubkeyAuthentication no \
\
PasswordAuthentication yes \
PermitEmptyPasswords no \
IgnoreRhosts yes \
HostbasedAuthentication no \
ChallengeResponseAuthentication no \
UsePAM yes \
\
AllowAgentForwarding no \
AllowTcpForwarding no \
X11Forwarding no \
PrintMotd no \
TCPKeepAlive yes \
\
PermitUserEnvironment no \
LoginGraceTime 1m \
ClientAliveInterval 2m \
LogLevel INFO \
PrintLastLog yes \
\
# no default banner path \
Banner /etc/issue.net \
\
# Allow client to pass locale environment variables \
AcceptEnv LANG LC_* \
\
# override default of no subsystems \
Subsystem sftp /usr/lib/openssh/sftp-server\
\
DebianBanner no" > /etc/sshd_config

chmod 600 /etc/ssh/sshd_config


## Test

sshd -T

systemctl reload sshd

#############
# Hardening #
#############

rm -f /etc/ssh/ssh_host_*

ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv -f /etc/ssh/moduli.safe /etc/ssh/moduli

sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

if [[ $(cat /etc/os-release | grep -i "Buster" | wc -l) -ne 0 ]]; then
	echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" >> /etc/ssh/sshd_config
else
	if [[ $(cat /etc/os-release | grep -i "Ubuntu 20.04" | wc -l) -ne 0 ]]; then
		echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf
	else
		echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf
	fi
fi

service ssh restart
