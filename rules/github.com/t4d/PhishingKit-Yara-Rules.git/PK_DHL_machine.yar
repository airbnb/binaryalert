rule PK_DHL_machine : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-23"
        comment = "Phishing Kit - DHL - 'Scripted by Machine'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "source"
        $spec_file1 = "revert.php"
        $spec_file2 = "Message.txt"
        $spec_file3 = "blocker.php"
        $spec_file4 = "ship.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
