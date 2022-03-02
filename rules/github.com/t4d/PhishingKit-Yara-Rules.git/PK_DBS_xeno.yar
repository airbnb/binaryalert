rule PK_DBS_xeno : DBS
{
    meta:
        description = "Phishing Kit impersonating DBS bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-26"
        comment = "Phishing Kit - DBS - 'By Xeno'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_file1 = "otp-mail.php"
        $spec_file2 = "token.php"
        $spec_file3 = "iframe.html"
        $spec_file4 = "auth.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
