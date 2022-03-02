rule PK_AdobePDF_hse : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF online"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-07-25"
        comment = "Phishing Kit - Adobe PDF Online - 'Hades Silent Exploits'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "adobe"
        // specific file found in PhishingKit
        $spec_file = "index.php"
        $spec_file2 = "login.php"
        $spec_file3 = "logg.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}