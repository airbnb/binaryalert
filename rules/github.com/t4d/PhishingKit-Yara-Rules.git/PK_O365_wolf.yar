rule PK_O365_wolf : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-05"
        comment = "Phishing Kit - O365 - 'Wolf-updated'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "script"
        // specific files found in PhishingKit
        $spec_file = "share-point.css"
        $spec_file2 = "throwit_first.php"
        $spec_file3 = "verificationAttempt.php"

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