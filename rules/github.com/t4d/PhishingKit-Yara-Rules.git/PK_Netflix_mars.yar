rule PK_Netflix_mars : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-23"
        comment = "Phishing Kit - Netflix - 'Mars - B i g s e c  C o m m u n i t y'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "inc"
        $spec_dir1 = "admin"
        $spec_dir2 = "antibots"
        // specific file found in PhishingKit
        $spec_file = "antibot_phishtank.php"
        $spec_file2 = "nfLogo.svg"
        $spec_file3 = "click.php"
        $spec_file4 = "settings.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
         all of ($spec_file*)
}