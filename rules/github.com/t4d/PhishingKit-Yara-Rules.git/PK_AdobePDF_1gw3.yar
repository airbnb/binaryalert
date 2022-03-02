rule PK_AdobePDF_1gw3 : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF Online"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-27"
        comment = "Phishing Kit - Adobe PDF Online - '1GW3 HACKZ'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "files"
        // specific file found in PhishingKit
        $spec_file = "error.php"
        $spec_file2 = "post.php"
        $spec_file3 = "logo.jpg"
        $spec_file4 = "bootstrap.min.js.js"
        $spec_file5 = "jquery.min.js.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}

