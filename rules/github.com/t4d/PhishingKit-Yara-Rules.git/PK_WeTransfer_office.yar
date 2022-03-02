rule PK_WeTransfer_office : WeTransfer
{
    meta:
        description = "Phishing Kit impersonating WeTransfer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-04"
        comment = "Phishing Kit - WeTransfer - '$subject = New Wetransfer Office'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "login"
        // specific file found in PhishingKit
        $spec_file = "core.php"
        $spec_file1 = "postLogin.php"
        $spec_file2 = "downloads.php"
        $spec_file3 = "robots.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_dir and 
        all of ($spec_file*)
}