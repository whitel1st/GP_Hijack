
# GroupPolicy Hijacking


---

## Warning

Current version of a script will turns on karma smb for all smb traffic.
So when you MiTM your victim and his DC (domain controller), all SMB functionality excep those that need for a Group Policy hijacking **will be lost**! 

---

**Version 1.0**

This script allows you to exploit Group Policy Hijacking attack to get an RCE.

What it does:

**Setup mode**

* Download and setup Impacket (which consists karmaSMB)
* Create necessary files: config and different files to be returned by karma SMB
* Create malicious payload via msfvenom or choose your own script
* Copy paylod to relevant folder
 
**Run mode**

* Check and if necessary creates iptables rules for supplied IP addresses
* Check and if necessary run `apache2` or `vsftpd`
* Increment version `GPT.ini`
* Run karmaSMB with created config (created in setup mode)
* Write logs of karmaSMB activity

**Config mode**

* Change a way of the shell delivering 
* Change type of the shell: custom or msf

**Read mode**

* Read config created in setup mode  


## Related research/articles 

- [[MWR Labs] How to own any Windows network with group policy hijacking attacks](https://labs.mwrinfosecurity.com/blog/how-to-own-any-windows-network-with-group-policy-hijacking-attacks/)
