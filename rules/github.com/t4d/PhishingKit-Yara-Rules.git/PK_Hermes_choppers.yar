rule PK_Hermes_choppers : Hermes
{
    meta:
        description = "Phishing Kit impersonating Hermes"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-12"
        comment = "Phishing Kit - Hermes - '#Choppers Fullz'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "datalog"
        $spec_dir2 = "includes"
        $spec_file1 = "complete.php"
        $spec_file2 = "CONFIG.php"
        $spec_file3 = "zero.php"
        $spec_file4 = "track.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
