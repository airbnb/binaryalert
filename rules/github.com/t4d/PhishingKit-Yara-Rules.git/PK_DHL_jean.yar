rule PK_DHL_jean : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-19"
        comment = "Phishing Kit - DHL - '$jean_email'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "jean"
        $spec_file1 = "Sys.php"
        $spec_file2 = "paris.php"
        $spec_file3 = "casa.php"
        $spec_file4 = "express-checkout.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
