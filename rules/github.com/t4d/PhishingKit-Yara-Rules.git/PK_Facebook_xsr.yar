rule PK_Facebook_xsr : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-29"
        comment = "Phishing Kit - Facebook - 'This Phishing Page Has Powerd By XSR.404'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "static.xx.fbcdn.net"
        // specific file found in PhishingKit
        $spec_file = "QzsHSoWJZTl.css"
        $spec_file2 = "email.php"
        $spec_file3 = "Read Me!!.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}

