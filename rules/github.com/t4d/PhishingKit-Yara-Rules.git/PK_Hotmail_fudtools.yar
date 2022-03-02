rule PK_Hotmail_fudtools : Hotmail
{
    meta:
        description = "Phishing Kit impersonating Hotmail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-26"
        comment = "Phishing Kit - Hotmail - 'Created BY fudtools[.]com'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        // specific file found in PhishingKit
        $spec_file = "thankyou.html"
        $spec_file2 = "mailer.php"
        $spec_file3 = "outlook_cover_640x360.jpg"
        $spec_file4 = "hosted-exchange-logo.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}

