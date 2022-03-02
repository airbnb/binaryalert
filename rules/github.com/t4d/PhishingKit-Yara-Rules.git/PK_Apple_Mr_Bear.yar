rule PK_Apple_Mr_Bear
{
    meta:
        description = "Apple phishing kit created by Mr Bear"
        licence = ""
        author = "Guido Denzler"
        reference = ""
        date = "2020-02-25"
        comment = "Phishing Kit - Apple - Mr Bear"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "MP1.php"
        $spec_file2 = "sdk.php"
        $spec_image1 = "payments.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file
        and 2 of ($spec_file*)
        and any of ($spec_image*)
}
