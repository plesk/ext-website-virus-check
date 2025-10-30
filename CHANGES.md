# 1.4.3 (3 Oct 2025)

* [*] Updated the extension to be fully compatible with PHP 8.4.

# 1.4.2 (6 May 2024)

* [-] The "PHP Deprecated Construction: Creation of dynamic property Modules_WebsiteVirusCheck_PleskDomain" error no longer appears in /var/log/plesk/panel.log in Plesk for Linux and in %plesk_dir%\admin\logs\php_error.log in Plesk for Windows. (EXTPLESK-5512)

# 1.4.1 (17 February 2023)

* [*] Internal improvements.

# 1.4 (29 May 2017)

* [-] Fix issue [\#21](https://github.com/plesk/ext-website-virus-check/issues/21): Provide option to disable domain name resolving

# 1.3 (3 May 2017)

* [-] Fix issue [\#18](https://github.com/plesk/ext-website-virus-check/issues/18): Need to skip old VirusTotal detected urls and samples

# 1.2 (3 April 2017)

* [+] Selectively disabling scan for sites
* [+] Show count for bad URLs and samples that communicate with this site
* [-] Fix issue [\#4](https://github.com/plesk/ext-website-virus-check/issues/4): Need to gracefully handle HTTP time outs to virustotal.com

# 1.1 (30 August 2016)

* [+] E-mail notifications
