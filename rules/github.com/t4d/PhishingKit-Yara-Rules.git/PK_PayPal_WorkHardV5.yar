
rule PK_PayPal_WorkHardV5
{
    meta:
        description = "PayPal phishing kit created by WorkHard"
        licence = ""
        author = "Guido Denzler"
        reference = ""
        date = "2020-02-25"
        comment = "Phishing Kit - PayPal - WorkHard"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "newdir.php"
        $spec_file2 = "ran.php"
        $spec_file3 = "makelang.php"
        $spec_file4 = "Work-Hard-V5"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file
        and 2 of ($spec_file*)
}
