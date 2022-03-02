rule PK_Optimum_conan : Optimum
{
    meta:
        description = "Phishing Kit impersonating Optimum"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-15"
        comment = "Phishing Kit - Optimum - '[ C O N A N ]'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "auth"
        $spec_file1 = "3.php"
        $spec_file2 = "hostname_check.php"
        $spec_file3 = "info/Email.php"
        $spec_file4 = ".htaccess"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
