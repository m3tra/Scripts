#!/bin/bash

# Check for sudo privilege
if [[ $EUID -ne 0 ]]; then
	echo "$0 requires sudo."
	exit 2
fi


################
# Installation #
################

## Install
sudo apt install vsftpd -y


## Enable service
sudo systemctl enable vsftpd
sudo systemctl start vsftpd


## Create FTP root directory
sudo mkdir ~/ftp
sudo chown nobody:nobody ~/ftp
sudo chmod a-w ~/ftp

sudo mkdir ~/ftp/files
sudo chown $USER:$USER ~/ftp/files


########################
# Server configuration #
########################

## Back up old config
sudo mv /etc/vsftpd.conf /etc/vsftpd.conf.bak


## Write new config
sudo echo " \
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
force_dot_files=YES

pasv_min_port=40000
pasv_max_port=50000

user_sub_token=$USER
local_root=/home/$USER/ftp

userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO \
" > /etc/vsftpd.conf


## Whitelist current user
sudo echo $USER > /etc/vsftpd.userlist


## Restart vsftpd service
sudo systemctl restart vsftpd.service


##############################
# Secure FTP Server with TLS #
##############################

## Create an SSL Certificate
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem


## Append TLS config to config file
sudo echo " \
ssl_enable=YES
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH \
" >> /etc/vsftpd.conf


## Restart vsftpd service
sudo systemctl restart vsftpd.service


############
# Firewall #
############

## Write vsftpd UFW application profile
sudo echo " \
[vsftpd]
title=Secure FTP Daemon
description=TLS encrypted FTP server
ports=20,21,990/tcp|40000:50000/tcp \
" > /etc/ufw/applications.d/vsftpd


## Allow vsftpd application through firewall
sudo ufw allow from 192.168.0.0/16 to any app vsftpd
sudo ufw allow from 10.51.195.0/24 to any app vsftpd
