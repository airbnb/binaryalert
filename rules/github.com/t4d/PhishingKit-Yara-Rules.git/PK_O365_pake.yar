rule PK_O365_pake : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-26"
        comment = "Phishing Kit - O365 - using pake.ico file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "manager"
        // specific files found in PhishingKit
        $spec_file = "pake.ico"
        $spec_file2 = "geoplugin.class.php"
        $spec_file3 = "ellipsis_white.svg"
        $spec_file4 = "one nation.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}