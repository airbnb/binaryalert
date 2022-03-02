rule PK_DiePost_Baronn : DiePost
{
    meta:
        description = "Phishing Kit impersonating Die Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-12-29"
        comment = "Phishing Kit - DiePost - '- Baronn -'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "packeges"
        $spec_file1 = "waiting.php"
        $spec_file2 = "Audience.txt"
        $spec_file3 = "first221.php"
        $spec_file4 = "i.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
