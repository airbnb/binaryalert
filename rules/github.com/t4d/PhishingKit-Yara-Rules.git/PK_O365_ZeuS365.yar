
rule PK_O365_ZeuS365
{
    meta:
        description = "O365 phishing kit created by ZeuS365"
        licence = ""
        author = "Guido Denzler"
        reference = ""
        date = "2020-02-25"
        comment = "Phishing Kit - O365 - ZeuS365"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "security-assurance.php"
        $spec_file2 = "enterpassword.php"
        $spec_file3 = "enterpasswordagain.php"
        $spec_file4 = "retry.php"
        $spec_image1 = "Office-365-Logo.png"
        $spec_image2 = "outlook.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file
        and 2 of ($spec_file*)
        and any of ($spec_image*)
}
