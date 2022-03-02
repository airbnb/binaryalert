rule PK_Apple_travel_partner : Apple
{
    meta:
        description = "Phishing Kit impersonating Apple"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://phishingkittracker.blogspot.com/2019/05/travel-partner-phishing-kit-type.html"
        date = "2021-09-23"
        comment = "Phishing Kit - Apple - '[ $$ Travel Partner Apple V 1.5 $$ ]'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_file1 = "One_Time.php"
        $spec_file2 = "setoransnsv.php"
        $spec_file3 = "messageapp.php"
        $spec_image1 = "ip_range_check.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*) and
        any of ($spec_image*)
}
