rule PK_Lloyds_live : Lloyds
{
    meta:
        description = "Phishing Kit impersonating Lloyds bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-21"
        comment = "Phishing Kit - Lloyds - '$database = lloyds_live'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "admin"
        $spec_dir2 = "admin"
        $spec_file1 = "Phonenumber.php"
        $spec_file2 = "Memorable.php"
        $spec_file3 = "Call.php"
        $spec_file4 = "dashboard.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
