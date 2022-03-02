rule PK_OneDrive_cloud : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-20"
        comment = "Phishing Kit - OneDrive - 'Title: OneDrive cloud'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_file1 = "body-bg.jpg"
        $spec_file2 = "blocker.php"
        $spec_file3 = "header.php"
        $spec_file4 = "onedrive.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for files
        all of ($spec_file*)
}