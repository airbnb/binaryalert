rule PK_Apple_z0n51
{
    meta:
        description = "Apple phishing kit created by Z0n51"
        licence = ""
        author = "Guido Denzler"
        reference = ""
        date = "2020-02-25"
        comment = "Phishing Kit - Apple - Z0n51"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "z0n51/confirm_billing_address"
        $spec_file2 = "z0n51/confirm_cc.php"
        $spec_file3 = "z0n51/sms.php"
        $spec_image1 = "herobg.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file
        and all of ($spec_file*)
        and any of ($spec_image*)
}
