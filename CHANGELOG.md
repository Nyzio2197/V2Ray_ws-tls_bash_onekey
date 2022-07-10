## 2020-06-11
* Switching from v2ray to v2fly
* mtproxy installation offline

## 2020-6-5
* Add ws tls Quantmumult import
* Add multi-threaded compilation
* Fix duplicate cron add issue
## 2020-6-3
* Add Nginx ipv6 listener TLS1.3 0 RTT (merge)
* Adapt Nginx ipv6 listening port changes
* Changed Nginx version 1.16.1 to 1.18.0
* Change ws path length from fixed 8 bits to range random length

## 2020-2-16
1.1.0
* Fix an issue where certificate updates were not applied correctly
* Add old configuration file retention
* Add installation process TLS version selection
* Change v2ray_qr_config_file location
* Fix v2ray daemon judgment logic error
* Add Nginx conflict detection

## 2020-2-7
1.0.7
* Fix automatic certificate update Nginx restart exception
* Fix bbr4-in-1 403 forbidden issue
* Fix some temporary file cleanup exceptions.
* Change default to keep only TLS1.3
* Add uninstall to provide Nginx retention options
* Add Nginx configuration file XFF thanks to tg:@Cliwired
* Add ws DOH configuration Thanks tg:@auth_chain_b

## 2020-01-25
* Fix missing curl dependencies
* Add MT-proxy-go installation code, thanks to whunt1 for this contribution
* Fix the problem that the test issuance succeeds but the official issuance fails, and the subsequent reinstallation causes the skipped certificate issuance.

## 2019-12-30 
> Please note that this update has more content and some code refactoring and merging. We suggest users to uninstall and reinstall the corresponding version when using the new management script.
* New interactive menu, refactored to install management script, version number initialized to 1.0, many functions merged
* Merge h2 version to main version and follow the update, h2 version (old version) is not maintained
* New option to change UUID ALTERID PORT TLS version
* Added V2ray logging and viewing
* Added 4 in 1 bbr sharpening script, thanks to 94ish.me 
* New uninstall option
* New certificate manual update, same principle as scheduled task update, certificate validity is only less than 30 days can be updated, default does not enable forced update

## 2019-11-28
* Add dependency rng-tools haveged to improve the replenishment rate of the system entropy pool
* Another double whammy... Fix the Nginx reboot issue that prevents it from booting up after a reboot
## 2019-11-27
* Adjusted certificate issuance detection from 0am Sunday to 3am Sunday
* Add parameter boost to allow direct use of 4-in-1 bbr/razor script
* Adjust parameter tls_modify to be compatible with TLS1.1 Select on demand
## 2019-11-26
> This version may solve the ancestral broken flow metaphysics problem of ws tls, please execute the installation script to update if needed
* TLS configuration modified to support 1.2 1.3 can be switched via tls_modify option
* Uninstall feature support can be uninstalled via the uninstall option
### 2019-10-17
> Suggest that users who encounter problems reset the system and reinstall it
* Changes Add Nginx systemd serverfile
* Fix Another double attempt to fix the Nginx boot-up issue
### 2019-10-16
* Adapted to Centos8 Debian10 Ubuntu19.04
* Fix the problem that scheduled tasks don't work on some systems
* Fix the bug that time synchronization service cannot be installed under Centos8.
* Fix the problem that certificate is not updated automatically under some systems.
* Fix the problem that Nginx boot configuration does not work on some systems.
* Changed not to repeat certificate application for the same domain name when installing repeatedly to prevent Let's encrypt API count limit
* Change default alterID 64 -> 4 to reduce resource usage
* Change nginx installation method from source to compile and install, and use new Openssl version with tls1.3 support
* Change nginx configuration file ssl_protocols ssl_ciphers to support tls1.3
* Changes Remove Debian8 Ubuntu 16.04 adaptation (may still be available in this version)
* Change default page disguised as html5 mini-game
* New install completed, node configuration information left on file
* Added use custom certificate
* New link import import
* Add QR code import
## 2018-04-10
* vmess+http2 over tls script update
## 2018-04-08
v3.3.1 (Beta)
* Minor adjustments to installation dependencies
* Readme content tweaks
## 2018-04-06
v3.3(Beta)
* Fix Nginx startup failure after Ubuntu 16.04/17.10 installation
* Fix duplicate Nginx installation source addition due to duplicate script execution
* Fix Nginx startup failure due to abnormal Nginx configuration file caused by repeated script execution
* Fix Nginx versioning issues caused by incorrectly adding Nginx Ubuntu sources
## 2018-04-03
V3.2(Beta)
* Update Nginx version to mainline version
* Add TLS1.3 http2 to Nginx configuration
## 2018-03-26
V3.1(Beta)
* 1. Remove irrelevant dependencies
* 2. Installation order changed, SSL generation at the end of the program
* 3. NGINX installation version unified to the latest stable version (ready for possible future http2 and tls1.3 adaptations, debian source default NGINX version is too low to support http2)
## 2018-03-18
V3.0(Stable)
* 1. Fix Bad Request issue when accessing specific pseudo Paths during Path triage (unified as 404 Not Found)
## 2018-03-10
V3.0(beta)
* 1. Code refactoring for some functions
* 2. Added 301 redirect, i.e. http forced jump to https 
* 3. added page disguise (a calculator program)
* 4. changed the disguise path from /ray/ to randomly generated
## 2018-03-05
V2.1.1(stable)
* 1. change Try to auto-kill related processes after detecting port occupation
* 2. try to fix GCE default pure template port 80 occupation problem (waiting for more feedback)
## 2018-02-04
V2.1.1(stable)
* 1. change local_ip judgment method from local NIC to command to get public IP.
* 1. fix the problem of mismatch between domain dns resolution IP and local IP
## 2018-01-28
v2.1.1(stable)
* 1. fix the port occupancy exception caused by lack of lsof dependency
## 2018-01-27
v2.1.1(stable)
* 1. Fix the installation failure issue caused by lack of crontab (scheduled task) dependency in some models
* 2. Improve the port occupation judgment
## 2017-12-06
V2.1 (stable)
* 1. fix the problem that Centos7 can't find the Nginx installation package
* 2. Improve SElinux configuration process reminder logo

V2.0 (stable)
* 1. Add Centos7 system support.
* 2. add custom port and custom alterID
* 3. Improve installation dependencies.
* 4. Fix the installation interruption problem caused by the abnormal version judgment of Ubuntu series systems.
* 5. Fix bug

V1.02(beta)
* 1. Add system decision, currently only support newer mainstream development systems with systemd.
* 2. refactor the local IP acquisition method

## 2017-12-05

V1.01 (beta)
* 1. Improve support for Debian9
* 2. fix a local ip error caused by Debian9 not installing net-tools by default
* 3. fix bc installation problem
* 4. Add the option to continue installation if the ip is not consistent (due to some vps' special situation, the intranet IP or its own NIC information is determined, or the public IP is not consistent with the information in the service period, etc.)

V1.0 (beta)
* 1. Currently only support Debian 8+ / Ubuntu 16.04+ 
* 2. Gradually improving

