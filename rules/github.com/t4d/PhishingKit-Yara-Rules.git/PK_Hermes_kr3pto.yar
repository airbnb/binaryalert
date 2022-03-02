rule PK_Hermes_kr3pto : Hermes
{
    meta:
        description = "Phishing Kit impersonating Hermes"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-15"
        comment = "Phishing Kit - Hermes - 'Hermes Fullz'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "hermes_files"
        $spec_dir2 = "logz"
        $spec_file1 = "str.php"
        $spec_file2 = "device_detect.php"
        $spec_file3 = "ant.php"
        $spec_file4 = "blacklist.dat"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
