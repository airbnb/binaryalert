rule PK_MetroBank_arandomo : MetroBank
{
    meta:
        description = "Phishing Kit impersonating Metrobank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-19"
        comment = "Phishing Kit - MetroBank - '$scamname=ARANDOMO'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Metrobank_files"
        $spec_file1 = "resfast.php"
        $spec_file2 = "request-otp.php"
        $spec_file3 = "zult.php"
        $spec_file4 = "protector.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and 
        // check for files
        all of ($spec_file*)
}
