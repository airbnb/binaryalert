rule PK_RoyalMail_RMtaxClaim : RoyalMail
{
    meta:
        description = "Phishing Kit impersonating RoyalMail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/JCyberSec_/status/1392112310785875988"
        date = "2021-05-11"
        comment = "Phishing Kit - RoyalMail - RMtaxClaim (@JCyberSec_)"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "mustangostang"
        // specific file found in PhishingKit
        $spec_file = "check.php"
        $spec_file2 = "payment.php"
        $spec_file3 = "intro.php"
        $spec_file4 = "control.php"
        $spec_file5 = "visits.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}