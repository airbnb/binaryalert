rule PK_ChinaLogin_Machine : chinese_Email_verification
{
    meta:
        description = "Phishing Kit stealing email credentials in chinese"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-16"
        comment = "Phishing Kit - Email Verification - 'Scripted by Machine'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "25GB"
        // specific file found in PhishingKit
        $spec_file = "Message.txt"
        $spec_file2 = "none.php"
        $spec_file3 = "error.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3
}

