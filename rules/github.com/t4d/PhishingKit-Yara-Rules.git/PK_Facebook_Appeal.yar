rule PK_Facebook_Appeal : Facebook
{
    meta:
        description = "Phishing Kit Impersonating Facebook Help Portal"
        licence = "GPL-3.0"
        author = "Krishnan Subramanian"
        reference = ""
        date = "2021-01-05"
        comment = "Phishing Kit - Facebook Help Portal"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "appeal"
        $cond_file1 = "lol1.php"
        $cond_file2 = "lol.php"
        $spec_file1 = "checkpoint.php"
        $spec_file2 = "sub2fac.php"
        $spec_file3 = "2fac.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        ($cond_file1 or $cond_file2) and
        all of ($spec_file*)
}
