rule PK_O365_schama : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-26"
        comment = "Phishing Kit - Office 365 - 'MAIL from Office.com Schama Page'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "/n/"
        $spec_file1 = "savePass.php"
        $spec_file2 = "index.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}