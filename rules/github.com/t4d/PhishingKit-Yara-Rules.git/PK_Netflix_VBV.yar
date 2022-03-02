rule PK_Netflix_VBV : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-20"
        comment = "Phishing Kit - Netflix - using '_XVBVX_.php' script"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "nfx"
        // specific file found in PhishingKit
        $spec_file = "__CONFIG__.php"
        $spec_file2 = "Warning.php"
        $spec_file3 = "sayron.php"
        $spec_file4 = "_XVBVX_.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
         all of ($spec_file*)
}