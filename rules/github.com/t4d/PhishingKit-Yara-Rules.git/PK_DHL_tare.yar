rule PK_DHL_tare : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-08"
        comment = "Phishing Kit - DHL - 'Created in 2014 By tare_ama'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "DHL_files"
        $spec_file1 = "deliveryform.php"
        $spec_file2 = "DHL.php"
        $spec_file3 = "tracking2.php"
        $spec_file4 = "mailar222.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
