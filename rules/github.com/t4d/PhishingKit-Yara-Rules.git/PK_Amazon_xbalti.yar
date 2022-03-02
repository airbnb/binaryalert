rule PK_Amazon_xbalti : Amazon
{
    meta:
        description = "Phishing Kit impersonating Amazon"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-11"
        comment = "Phishing Kit - Amazon - 'BY XBALTI'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "XBALTI"
        $spec_dir1 = "amazon"
        $spec_file1 = "rezulta.php"
        $spec_file2 = "check_bin.php"
        $spec_file3 = "send_billing.php"
        $spec_file4 = "antibots.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}