rule PK_Vodafone_arcor : Vodafone
{
    meta:
        description = "Phishing Kit impersonating Vodafone"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-11-02"
        comment = "Phishing Kit - Vodafone - 'arcor_files'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "arcor_files"
        $spec_file1 = "arcor.htm"
        $spec_file2 = "login2.php"
        $spec_file3 = "mafo.js"
        $spec_file4 = "2x2.htm"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
