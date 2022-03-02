rule PK_Facebook_xfinity : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-22"
        comment = "Phishing Kit - Facebook - '= xfinity login info ='"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "image"
        // specific file found in PhishingKit
        $spec_file = "valid-Card.php"
        $spec_file2 = "sdewewe images (4).jpeg"
        $spec_file3 = "xfinity.svg"
        $spec_file4 = "creadit-card.php"
        $spec_file5 = "choose-an-option.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}

