rule PK_Santander_unknown : Santander
{
    meta:
        description = "Phishing Kit impersonating Santander"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-06-11"
        comment = "Phishing Kit - Santander - 'unknown'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "cnt.png"
        $spec_file2 = "email.php"
        $spec_file3 = "surf3.php"
        $spec_file4 = "need2.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}