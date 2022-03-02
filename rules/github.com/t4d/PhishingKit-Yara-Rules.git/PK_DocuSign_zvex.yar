rule PK_DocuSign_zvex : DocuSign
{
    meta:
        description = "Phishing Kit impersonating DocuSign"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-28"
        comment = "Phishing Kit - DocuSign - 'zVeXn*.php'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "liamg2.php"
        $spec_file2 = "loa.php"
        $spec_file3 = "zVeXn2.php"
        $spec_file4 = "zVeXn1.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
