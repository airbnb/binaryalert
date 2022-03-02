rule PK_Apple_xbalti : Apple
{
    meta:
        description = "Phishing Kit impersonating Apple"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-12-16"
        comment = "Phishing Kit - Apple - 'BY XBALTI'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "XBALTI"
        $spec_file1 = "yassin.css"
        $spec_file2 = "Congratulation.php"
        $spec_file3 = "Secure.php"
        $spec_image1 = "img/Apple_logo_grey.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*) and
        any of ($spec_image*)
}