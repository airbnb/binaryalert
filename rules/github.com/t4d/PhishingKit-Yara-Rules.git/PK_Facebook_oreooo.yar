rule PK_Facebook_oreooo : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-10-04"
        comment = "Phishing Kit - Facebook - 'THIS SCAM WAS CREATED BY #OREOO'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "home"
        // specific files found in PhishingKit
        $spec_file = "send_login.php"
        $spec_file2 = "system.php"
        $spec_file3 = "BOT_6.php"
        $spec_file4 = "DJTV3bRb1M3.js.download"
        $spec_file5 = "2.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}
