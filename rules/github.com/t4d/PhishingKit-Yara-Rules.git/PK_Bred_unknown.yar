rule PK_Bred_unknown : BRED
{
    meta:
        description = "Phishing Kit impersonating BRED - Banque Populaire"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-18"
        comment = "Phishing kit - BRED - '- unknown -'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "image"
        // specific file found in PhishingKit
        $spec_file = "tele.php"
        $spec_file2 = "loading1.php"
        $spec_file3 = "logozz.png"
        $spec_file4 = "sms1.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}