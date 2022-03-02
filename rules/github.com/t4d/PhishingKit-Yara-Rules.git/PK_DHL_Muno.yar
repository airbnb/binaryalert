rule PK_DHL_Muno : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-19"
        comment = "Phishing Kit - DHL - 'Anonymous Muno'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "index2"
        $spec_file1 = "Secinfo.php"
        $spec_file2 = "u.php"
        $spec_file3 = "hello.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
