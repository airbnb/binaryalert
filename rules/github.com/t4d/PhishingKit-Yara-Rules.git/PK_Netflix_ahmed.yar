rule PK_Netflix_ahmed : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-12-06"
        comment = "Phishing Kit - Netflix - 'mail_to ahmed | FULLZ'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "assets"
        $spec_dir2 = "actions"
        // specific file found in PhishingKit
        $spec_file = "cards.php"
        $spec_file2 = "Email.php"
        $spec_file3 = "anti3.php"
        $spec_file4 = "logs.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}