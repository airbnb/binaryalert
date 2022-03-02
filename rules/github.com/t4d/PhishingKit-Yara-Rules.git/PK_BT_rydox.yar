rule PK_BT_rydox : BT
{
    meta:
        description = "Phishing Kit impersonating BT Business"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-29"
        comment = "Phishing Kit - BT Business - 'Rydox.CC Coding'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "img"
        $spec_file1 = "app.css"
        $spec_file2 = "search.svg"
        $spec_file3 = "login2.php"
        $spec_file4 = "index2.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
