rule PK_Netflix_xFraudv1 : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-12"
        comment = "Phishing Kit - Netflix - 'xFraud scams - netflix v1'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "actions/auth.php"
        $spec_file2 = "account/done.php"
        $spec_file3 = "inc/config.inc.php"
        $spec_file4 = "assets/vbv.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
         all of ($spec_file*)
}