rule PK_Netflix_ShadowZ118 : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-29"
        comment = "Phishing Kit - Netflix - 'scamname = shadow'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "rselt"
        $spec_file1 = "api/Config.php"
        $spec_file2 = "verification.php"
        $spec_file3 = "anti3.php"
        $spec_file4 = "amex_cvv.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
