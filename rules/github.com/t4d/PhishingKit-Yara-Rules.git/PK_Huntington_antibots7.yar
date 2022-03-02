rule PK_Huntington_antibots7 : Huntington
{
    meta:
        description = "Phishing Kit impersonating Huntington"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "hxxps://antibots7.com/"
        date = "2021-05-17"
        comment = "Phishing Kit - Huntington - 'AnTiBoTs7'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "email-account_files"
        $spec_dir2 = "index_files"
        $spec_file1 = "config2.php"
        $spec_file2 = "email-account.php"
        $spec_file3 = "Email.php"
        $spec_file4 = "nuanceChat.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
