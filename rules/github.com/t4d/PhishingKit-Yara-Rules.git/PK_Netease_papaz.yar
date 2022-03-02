rule PK_Netease_papaz : Netease
{
    meta:
        description = "Phishing Kit impersonating Netease 163.com"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-12"
        comment = "Phishing Kit - qiye.163.com - 'PAPAZ & SON'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "img"
        $spec_file1 = "bizmail1.php"
        $spec_file2 = "next1.php"
        $spec_file3 = "bizmail.php"
        $spec_file4 = "qiyes.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}