rule PK_LinkedIn_MMBM : LinkedIn
{
    meta:
        description = "LinkedIn phishing kit created by MMBM"
        licence = ""
        author = "Guido Denzler"
        reference = ""
        date = "2020-02-25"
        comment = "Phishing Kit - LinkedIn - MMBM"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "vu.txt"
        $spec_file2 = "robots.txt"
        $spec_file3 = "loginss.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file
        and all of ($spec_file*)
}
