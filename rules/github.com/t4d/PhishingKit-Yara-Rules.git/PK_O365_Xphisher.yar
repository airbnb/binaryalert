rule PK_O365_Xphisher
{
    meta:
        description = "O365 phishing kit created by XXX"
        licence = ""
        author = "Guido Denzler"
        reference = ""
        date = "2020-02-25"
        comment = "Phishing Kit - O365 - XXX"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "logs.txt"
        $spec_file2 = "visitors.txt"
        $spec_file3 = "README.txt"
        $spec_file4 = "Your_email.php"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file
        and all of ($spec_file*)
}
