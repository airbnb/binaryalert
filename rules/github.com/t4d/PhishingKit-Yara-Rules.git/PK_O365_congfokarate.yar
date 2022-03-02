rule PK_O365_congfokarate : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-09-10"
        comment = "Phishing Kit - Office 365 - '$path =/home/congfokarate'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "includes"
        $spec_dir2 = "store"
        $spec_file1 = "user_details.php"
        $spec_file2 = "config.php"
        $spec_file3 = "email.php"
        $spec_file4 = "delete_function.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}