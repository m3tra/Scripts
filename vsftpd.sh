#!/bin/bash

################
# Installation #
################

if [[ $EUID -ne 0 ]]; then
	echo "$0 requires sudo."
	exit 2
fi

## Install
apt install vsftpd -y
echo ""


## Enable service
systemctl enable vsftpd
systemctl start vsftpd
echo ""

## Create FTP root directory
mkdir $LOGNAME/ftp
chown nobody:nobody $LOGNAME/ftp
chmod a-w $LOGNAME/ftp

mkdir $LOGNAME/ftp/files
chown $LOGNAME:$LOGNAME $LOGNAME/ftp/files


########################
# Server configuration #
########################

## Back up old config
mv /etc/vsftpd.conf /etc/vsftpd.conf.bak


## Write new config
echo \
"listen=YES
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

user_sub_token=$LOGNAME
local_root=/home/$LOGNAME/ftp

userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO" \
> /etc/vsftpd.conf


## Whitelist current user
echo $LOGNAME > /etc/vsftpd.userlist


## Restart vsftpd service
systemctl restart vsftpd.service
echo ""


##############################
# Secure FTP Server with TLS #
##############################

## Create an SSL Certificate
openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem
echo ""

## Append TLS config to config file
echo \
"ssl_enable=YES
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH" \
>> /etc/vsftpd.conf


## Restart vsftpd service
systemctl restart vsftpd.service
echo ""


############
# Firewall #
############

## Write vsftpd UFW application profile
echo \
"[vsftpd]
title=Secure FTP Daemon
description=TLS encrypted FTP server
ports=20,21,990,40000:50000/tcp" \
> /etc/ufw/applications.d/vsftpd


## Allow vsftpd application through firewall
ufw allow from 192.168.0.0/16 to any app vsftpd
ufw allow from 10.51.195.0/24 to any app vsftpd

ufw reload
