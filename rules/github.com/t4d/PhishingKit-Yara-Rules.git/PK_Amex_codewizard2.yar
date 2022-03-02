rule PK_Amex_codewizard2 : Amex
{
    meta:
        description = "Phishing Kit impersonating American Express"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-12"
        comment = "Phishing Kit - Amex - '=+Codewizard+='"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "home"
        $spec_file1 = "em2.php"
        $spec_file2 = "confirm1.php"
        $spec_file3 = "email2.php"
        $spec_file4 = "block.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}