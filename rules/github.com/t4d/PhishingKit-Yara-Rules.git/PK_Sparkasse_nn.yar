rule PK_Sparkasse_nn : Sparkasse
{
    meta:
        description = "Phishing Kit impersonating Sparkasse"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-17"
        comment = "Phishing Kit - Sparkasse - 'From: nn'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Sparkasse_files"
        // specific file found in PhishingKit
        $spec_file = "firedown.php"
        $spec_file2 = "index.htm"
        $spec_file3 = "sparkasse.css"
        $spec_file4 = "harsh2-0.png"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}