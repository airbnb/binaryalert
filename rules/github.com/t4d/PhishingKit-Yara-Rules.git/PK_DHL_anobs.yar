rule PK_DHL_anobs : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL (in chinese)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-31"
        comment = "Phishing Kit - DHL - '+ Created BY Mr-Anobs in 2016 (skype:ethan-miles) +'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "Logon2.php"
        $spec_file2 = "Secinfo.php"
        $spec_file3 = "tracking2.php"
        $spec_file4 = "DHL_China_logo.JPG"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
