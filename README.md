# Iptables extension for Wordfence

Adding Iptables capabilites to Wordfence plugin for Wordpress

# What is Wordfence?

Wordfence is a plugin for Wordpress, supplied in a free and premium (i.e. paid) versions. It's a Web Application Firewall allowing the user to check the security of a Wordpress instance and it's useful to a number of security tasks (IP blocking by various rules, auditing, scans, etc.). You may found every detail about it on its dedicated website at https://www.wordfence.com/

# The goal of this extension

Wordfence, among other things, is able to block the access from an IP to a Wordpress site once it detects malicious activities (ex. security scans or flooding). However, such traffic can still overload the work of your web server, since Wordfence can apply its blocks just when it is loaded by Wordpress. This task is resource intensive and can seriously affect the performance of your website.
This extension is able to access the database table where Wordfence logs the IP blocked for any reason and block them "upstream" by a system firewall (iptables). In this way your web server (tipically, Apache or nginx) has a much ligther traffic load to handle in case of an attack.

# How it works?

After you have cloned this git on your server, you need to look inside the file waf.ini and, at least, make sure the path of iptables included inside your server is correctly set in waf.ini.
You also need to edit the file waf.sh in order to set the paths of your websites you want to scan and the path where you installed this package (detailed instructions are included inside the file waf.sh). Also, make sure your bash shell is in /bin/bash, otherwise edit accordingly the "shebang" at the beginning of waf.sh.
After that, it suffices scheduling as root user the execution of waf.sh by your crontab, running the task every 5 or 10 minutes.
