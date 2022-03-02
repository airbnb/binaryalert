rule PK_SFExpress_sace : SFExpress
{
    meta:
        description = "Phishing Kit impersonating SF Express"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-06"
        comment = "Phishing Kit - SF Express - 'Created BY Mr-Sace in 2016 (skype: s.wright77)'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        // specific file found in PhishingKit
        $spec_file = "deliveryform.php"
        $spec_file2 = "Logon2.php"
        $spec_file3 = "Secinfo.php"
        $spec_file4 = "SF-Express-standard-LOGO-51884.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}