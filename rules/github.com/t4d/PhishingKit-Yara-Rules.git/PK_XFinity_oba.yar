rule PK_XFinity_oba : XFinity
{
    meta:
        description = "Phishing Kit impersonating XFinity"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-11"
        comment = "Phishing Kit - XFinity - 'Created BY OBA'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "activityi_data"
        $spec_file1 = "comcast_failed.login.php"
        $spec_file2 = "CDhiddenIframe.htm"
        $spec_file3 = "personal.php"
        $spec_file4 = "complete.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
