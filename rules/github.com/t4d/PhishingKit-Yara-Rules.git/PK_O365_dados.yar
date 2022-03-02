rule PK_O365_dados : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-14"
        comment = "Phishing Kit - Office 365 - exfiltrate into a file named dadoshotmail.txt"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "acessodes"
        $spec_dir1 = "acessomob"
        $spec_file1 = "autentica.php"
        $spec_file2 = "login-two.php"
        $spec_file3 = "loginpasso2.php"
        $spec_file4 = "logininicial.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}