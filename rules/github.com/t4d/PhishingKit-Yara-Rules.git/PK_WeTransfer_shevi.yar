rule PK_WeTransfer_shevi : WeTransfer
{
    meta:
        description = "Phishing Kit impersonating WeTransfer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-28"
        comment = "Phishing Kit - WeTransfer - 'WEtransfer Logx CoDeD By Shevi'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "cgi"
        // specific file found in PhishingKit
        $spec_file = "loading.php"
        $spec_file1 = "loading.php"
        $spec_file2 = "timeout.php"
        $spec_file3 = "login6.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_dir and 
        all of ($spec_file*)
}