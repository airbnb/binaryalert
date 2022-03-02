rule PK_LinkedIn_hakam : LinkedIn
{
    meta:
        description = "Phishing Kit impersonating LinkedIn"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-30"
        comment = "Phishing Kit - LinkedIn - $subject = 'HaKam Nation'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "hakamnew"
        $spec_file1 = "serro.php"
        $spec_file2 = "piled.php"
        $spec_file3 = "tops.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
