
# README #

**Version 1.0**

This script allow you to exploit SMB Hijacking attack.

What it does:

**Setup mode**

* Download and setup Impacket (which consists karmaSMB)
* Create necessary files: config and different files to be returned by karma SMB
* Create malicious payload via msfvenom or choose your own script
* Copy paylod to relevant folder
 
**Run mode**

* Check and if necessary creates iptables rules for supplied IP addresses
* Check and if necessary run apache2 or vsftpd
* Increment version GPT.ini
* Run karmaSMB with created config (created in setup mode)
* Write logs of karmaSMB activity

**Config mode**

* Change the way of delivering shell
* Change type of shell: custom or msf

**Read mode**

* Read config created in setup mode  

# To be done #

**Features**

[] - Priority from. 0 is the most significant

* [done] Add files with different extensions - for karmaSMB. Such files as .xml  
* [0] (Need more research) Stop redirecting ALL SMB2 TRAFFIC, because by doing so you ruin all SMB2 communications
* [1] (Not so interesting) Hide PowerShell window
