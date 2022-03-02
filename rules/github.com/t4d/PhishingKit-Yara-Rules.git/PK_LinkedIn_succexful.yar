rule PK_LinkedIn_succexful : LinkedIn
{
    meta:
        description = "Phishing Kit impersonating LinkedIn"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-30"
        comment = "Phishing Kit - LinkedIn - 'by Succexful Drizzy'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "index.html"
        $spec_file2 = "index2.html"
        $spec_file3 = "login.php"
        $spec_file4 = "login2.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for files
        all of ($spec_file*)
}
