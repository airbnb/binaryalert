rule WickrMe
{
    meta:
        id = "6yM5V73btyHP2BBFhj8cXv"
        fingerprint = "1c7f8412455ea211f7a1606f49151be31631c17f37a612fb3942aff075c7ddaa"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies WickrMe (aka Hello) ransomware."
        category = "MALWARE"
        malware = "WICKRME"
        malware_type = "RANSOMWARE"
        reference = "https://www.trendmicro.com/en_ca/research/21/d/hello-ransomware-uses-updated-china-chopper-web-shell-sharepoint-vulnerability.html"


    strings:
        $ = "[+] Config Service..." ascii wide
        $ = "[+] Config Services Finished" ascii wide
        $ = "[+] Config Shadows Finished" ascii wide
        $ = "[+] Delete Backup Files..." ascii wide
        $ = "[+] Generate contact file {0} successfully" ascii wide
        $ = "[+] Generate contact file {0} failed! " ascii wide
        $ = "[+] Get Encrypt Files..." ascii wide
        $ = "[+] Starting..." ascii wide
        $ = "[-] No Admin Rights" ascii wide
        $ = "[-] Exit" ascii wide

    condition:
        4 of them
}