rule PK_Chase_PremanKeyboard
{
    meta:
        description = "XXX phishing kit created by XXX"
        licence = ""
        author = "Guido Denzler"
        reference = ""
        date = "2020-02-25"
        comment = "Phishing Kit - XXX - XXX"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "verification-billing.php"
        $spec_file2 = "bt.php"
        $spec_image1 = "imgnortonsiteseal.png"
        $spec_image2 = "chase.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file
        and 2 of ($spec_file*)
        and any of ($spec_image*)
}
