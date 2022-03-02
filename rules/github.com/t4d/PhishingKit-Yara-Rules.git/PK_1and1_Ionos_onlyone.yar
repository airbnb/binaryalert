rule PK_1and1_Ionos_onlyone : one_and_one
{
    meta:
        description = "Phishing Kit impersonating IONOS by 1and1"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-12"
        comment = "Phishing Kit - 1and1 - 'By The Only One'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "img"
        $spec_dir2 = ".well-known"
        // specific file found in PhishingKit
        $spec_file = "inpagelayer.css"
        $spec_file2 = "apple-touch-icon.png"
        $spec_file3 = "index.html"
        $spec_file4 = "login.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}