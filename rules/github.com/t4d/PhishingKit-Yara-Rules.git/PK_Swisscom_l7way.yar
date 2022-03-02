rule PK_Swisscom_l7way : Swisscom
{
    meta:
        description = "Phishing Kit impersonating Swisscom"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-11"
        comment = "Phishing Kit - Swisscom - by 'l7way'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "log"
        // specific file found in PhishingKit
        $spec_file = "scamti.css"
        $spec_file2 = "dd.php"
        $spec_file3 = "cc.php"
        $spec_file4 = "smserror.php"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}