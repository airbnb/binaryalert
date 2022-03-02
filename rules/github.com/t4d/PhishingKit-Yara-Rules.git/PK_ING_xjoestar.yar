rule PK_ING_xjoestar : ING
{
    meta:
        description = "Phishing Kit impersonating ING bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-06-10"
        comment = "Phishing Kit - ING bank - xJOESTAR directory inside the phishing kit"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "ing"
        $spec_file1 = "code.php"
        $spec_file2 = "step6.php"
        $spec_file3 = "coo.php"
        $spec_file4 = "phone.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}