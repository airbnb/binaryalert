rule PK_Box_unknown : Box
{
    meta:
        description = "Phishing Kit impersonating Box"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-23"
        comment = "Phishing Kit - Box - 'Created BY Unknown'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Thank You!_files"
        $spec_file1 = "001100110011gmail.html"
        $spec_file2 = "fast.php"
        $spec_file3 = "box.html"
        $spec_file4 = "Thank You!.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
