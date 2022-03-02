rule PK_Metamask_koda : Metamask
{
    meta:
        description = "Phishing Kit impersonating Metamask"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-22"
        comment = "Phishing Kit - Metamask - '= koda ='"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Euclid"
        $spec_file1 = "error.php"
        $spec_file2 = "teak123M_______.txt"
        $spec_file3 = "wallet.html"
        $spec_file4 = "metamask-logo-horizontal.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}

