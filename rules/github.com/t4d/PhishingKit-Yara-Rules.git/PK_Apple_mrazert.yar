rule PK_Apple_mrazert : Apple
{
    meta:
        description = "Phishing Kit impersonating Apple"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-10"
        comment = "Phishing Kit - Apple - 'From: mrazert'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "system"
        $spec_file1 = "blocker.php"
        $spec_file2 = "sand_email.php"
        $spec_file3 = "send_carde.php"
        $spec_image1 = "system.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*) and
        any of ($spec_image*)
}