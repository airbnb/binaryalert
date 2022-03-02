rule PK_MWeb_Zimbra : MWeb
{
    meta:
        description = "Phishing Kit impersonating MWeb.co.za Zimbra login"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-25"
        comment = "Phishing Kit - MWeb - 'ZloginPanel'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "index_files"
        $spec_file1 = "need1.php"
        $spec_file2 = "common,login,zhtml,skin.css"
        $spec_file3 = "LoginBanner.png"
        $spec_file4 = "email.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
