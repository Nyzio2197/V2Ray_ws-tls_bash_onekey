## V2Ray Nginx-based vmess+ws+tls one-click installation script

> Thanks for non-commercial open source development authorization by JetBrains

### About VMess MD5 Authentication Information Phase-out Mechanism
> Starting January 1, 2022, compatibility with MD5 authentication messages will be disabled on the server side by default. Any client using MD5 authentication information will not be able to connect to a server with VMess MD5 authentication information disabled.

For affected users, we strongly recommend that you reinstall and set the alterid to 0 (the default value has now been changed to 0) and no longer use the VMess MD5 authentication mechanism!
If you do not want to reinstall, you can force compatibility with the MD5 authentication mechanism by using https://github.com/KukiSa/VMess-fAEAD-disable

### Telegram groups
* telegram exchange group:https://t.me/wulabing_v2ray 
* telegram update announcement channel: https://t.me/wulabing_channel

### Preparation
* Prepare a domain name and add the A record to it.
* [V2ray official instructions](https://www.v2ray.com/) for TLS WebSocket and V2ray related information
* Install wget

### Installation/update method (h2 and ws versions are merged)
Vmess+websocket+TLS+Nginx+Website
```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/nyzio2197/V2Ray_ws-tls_bash_onekey/master/install.sh" && chmod +x install.sh && bash install.sh
```

VLESS+websocket+TLS+Nginx+Website
```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/nyzio2197/V2Ray_ws-tls_bash_onekey/dev/install.sh" && chmod +x install.sh && bash install.sh
```

### Caution
* If you don't know the exact meaning of the settings in the script, use the default values provided by the script except for the domain name
* To use this script, you need to have basic Linux experience, knowledge of computer networking, and basic computer operation.
* Currently, Debian 9+ / Ubuntu 18.04+ / Centos7+ is supported. Some Centos templates may have compilation problems that are difficult to handle, so it is recommended that you change to another system template when you encounter compilation problems.
* The group owner only provides extremely limited support, so ask your friends if you have any questions.
* Every Sunday at 3:00 am, Nginx will automatically restart to match the certificate issuance timing task, during which the node cannot connect normally.

### Update log
> For updates, see CHANGELOG.md

### Acknowledgements
* ~~ Another branch version of this script (Use Host) is available at: https://github.com/dylanbai8/V2Ray_ws-tls_Website_onekey Please choose according to your needs ~~ This author may have stopped maintaining
* MTProxy-go TLS version project references https://github.com/whunt1/onekeymakemtg in this script Thanks to whunt1
* The original Razor 4 in 1 script is referenced in this script https://www.94ish.me/1635.html Thanks
* The modified version of the Razor 4 in 1 script in this script is referenced at https://github.com/ylx2016/Linux-NetSpeed Thanks to ylx2016

### Certificate
> If you already have the certificate file of the domain you are using, you can put the crt and key file named v2ray.crt v2ray.key in /data directory (if the directory does not exist, please create a directory first), please pay attention to the certificate file permission and certificate expiration date, please renew the certificate by yourself after the custom certificate expiration date

The script supports automatic generation of Let's Encrypt certificate, valid for 3 months, theoretically the automatically generated certificate supports automatic renewal

### View client configuration
`cat ~/v2ray_info.txt`

### V2ray Introduction

* V2Ray is an excellent open source web proxy tool that can help you experience the Internet smoothly, and currently has full platform support for Windows, Mac, Android, IOS, Linux and other operating systems.
* This script is a one-click fully configured script, after all processes are run normally, directly set up the client according to the output results and you can use it!
* Please note: We still strongly recommend you to understand the entire program workflow and principle

### It is recommended to set up only a single proxy for a single server
* This script installs the latest version of V2ray core by default
* The latest version of V2ray core is 4.22.1 (please also pay attention to the synchronization of client-side core updates, you need to ensure that the client-side kernel version >= server-side kernel version)
* It is recommended to use the default port 443 as the connection port
* You can replace the fake content by yourself.

### Caution
* It's is recommending to use this script in pure environment, if you are new to CentOs, please do not use CentOs system.
* Do not use this program in a production environment until you have tried this script and it does work.
* This program relies on Nginx for its functionality. Please pay special attention to users who have installed Nginx using [LNMP](https://lnmp.org) or other similar scripts that carry Nginx, as using this script may result in unpredictable errors (not tested, if it exists, this issue may be addressed in subsequent releases).
* Some of V2Ray's features depend on system time. Please make sure that the system UTC time error for your V2RAY application is within three minutes, regardless of time zone.
* This bash relies on [V2ray official installation script](https://install.direct/go.sh) and [acme.sh](https://github.com/Neilpang/acme.sh) to work.
* Centos system users should release the program-related ports (default: 80, 443) in the firewall in advance


### Startup method

Start V2ray: `systemctl start v2ray`

Stop V2ray: `systemctl stop v2ray`

Start Nginx: `systemctl start nginx`

Stop Nginx: `systemctl stop nginx`

### Related directories

Web directory: `/home/wwwroot/3DCEList`

V2ray server-side configuration: `/etc/v2ray/config.json`

V2ray client-side configuration: `~/v2ray_info.inf`

Nginx directory: `/etc/nginx`

Certificate files: `/data/v2ray.key and /data/v2ray.crt` Please note the certificate permission settings

### Support (wulabing)

You can use my Movers AFF to buy VPS

https://bandwagonhost.com/aff.php?aff=63939

You can use my justmysocks AFF to purchase a proxy provided by Movers and shakers

https://justmysocks.net/members/aff.php?aff=17621
