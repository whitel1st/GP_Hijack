
# GP Hijack automated #

**Version 1.0**

This script allows you to exploit Group Policy Hijacking attack.

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
* Change type of the shell: custom or msf

**Read mode**

* Read config created in setup mode  

# Terms of Use #

* Do NOT use this on any computer you do not own, or are allowed to run this on;
* Credits must always be given, With linksback to here;
* You may NEVER attempt to sell this, its free and open source;
* The authors and publishers assume no responsibility;
* For educational purposes only.
