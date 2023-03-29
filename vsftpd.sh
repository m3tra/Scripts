#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "$0 requires sudo."
	exit 2
fi

################
# Installation #
################

## Install

apt install vsftpd -y

service vsftpd status


## UFW RUles

echo "
[VSFTPD]
title=Secure FTP Daemon
description=TLS encrypted FTP server
ports=20,21,990/tcp|40000:50000/tcp
" > /etc/ufw/applications.d/vsftpd

ufw allow from 192.168.0.0/16 to any app vsftpd comment VSFTPD
ufw allow from 10.51.195.0/24 to any app vsftpd comment VSFTPD


## Create FTP root directory

mkdir ~/ftp
chown nobody:nobody ~/ftp
chmod a-w ~/ftp

mkdir ~/ftp/files
chown $USER:$USER ~/ftp/files


## Server configuration

mv /etc/vsftpd.conf /etc/vsftpd.conf.bak

echo "
listen=NO
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
userlist_deny=NO
" > /etc/vsftpd.conf


echo $USER > /etc/vsftpd.userlist

systemctl restart vsftpd.service

##############################
# Secure FTP Server with TLS #
##############################

## Create an SSL Certificate

openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem


## Configure TLS

echo "
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
ssl_ciphers=HIGH
" >> /etc/vsftpd.conf

systemctl restart vsftpd.service
