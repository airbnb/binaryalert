rule PK_USPS_aron : USPS
{
    meta:
        description = "Phishing Kit impersonating USPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-09-01"
        comment = "Phishing Kit - USPS - 'CODED BY ARON-TN'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "anti"
        // specific file found in PhishingKit
        $spec_file = "id.php"
        $spec_file2 = "index5.php"
        $spec_file3 = "anti8.php"
        $spec_file4 = "usps.png"
        $spec_file5 = "mailto.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}