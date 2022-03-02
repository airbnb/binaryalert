rule PK_DHL_Tracking : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-01"
        comment = "Phishing Kit - DHL - '$subject = Tracking#:'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "index.php"
        $spec_file2 = "next.php"
        $spec_file3 = "mail.php"
        $spec_file4 = "0.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
