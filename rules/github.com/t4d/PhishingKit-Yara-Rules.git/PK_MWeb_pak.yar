rule PK_MWeb_pak : MWeb
{
    meta:
        description = "Phishing Kit impersonating MWeb"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-12"
        comment = "Phishing kit - MWeb - presence of a pakistani ip address in source code"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "includes"
        $spec_dir1 = "store"
        // specific file found in PhishingKit
        $spec_file = "config.php"
        $spec_file2 = "user_details.php"
        $spec_file3 = "mweb-custom.css"
        $spec_file4 = "mweb-logo-2020-white.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}