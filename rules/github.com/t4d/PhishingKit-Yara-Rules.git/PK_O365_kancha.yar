rule PK_O365_kancha : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-03"
        comment = "Phishing Kit - Office 365 - kancha.php file into the phishing kit"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "captcha"
        $spec_file1 = "kancha.php"
        $spec_file2 = "getting.php"
        $spec_file3 = "captcha.php"
        $spec_file4 = "font.ttf"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}