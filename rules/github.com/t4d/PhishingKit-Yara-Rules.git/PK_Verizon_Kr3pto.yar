rule PK_Verizon_Kr3pto : Verizon
{
    meta:
        description = "Phishing Kit impersonating Verizon"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-26"
        comment = "Phishing Kit - Verizon - '// Kr3pto'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_file1 = "Pin.php"
        $spec_file2 = "Card.php"
        $spec_file3 = "config.php"
        $spec_file4 = "vzw-iconfont.ttf"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
