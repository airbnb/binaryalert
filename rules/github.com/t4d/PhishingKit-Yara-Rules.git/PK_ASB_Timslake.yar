rule PK_ASB_Timslake : ASB
{
    meta:
        description = "Phishing Kit impersonating ASB FastNet"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-19"
        comment = "Phishing Kit - ASB FastNet - 'Created By TimSLake'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Asb"
        $spec_file1 = "index.htm"
        $spec_file2 = "login.php"
        $spec_file3 = "Thankyou.htm"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
