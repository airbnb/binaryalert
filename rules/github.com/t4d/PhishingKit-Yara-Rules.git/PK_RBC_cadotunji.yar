rule PK_RBC_cadotunji : RBC
{
    meta:
        description = "Phishing Kit impersonating Royal Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-03"
        comment = "Phishing Kit - Royal Bank - 'Created By cadotunji'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "archive"
        $spec_file1 = "1.royalbank.html"
        $spec_file2 = "group1.php"
        $spec_file3 = "group2.php"
        $spec_file4 = "rb.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}