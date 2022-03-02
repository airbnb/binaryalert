rule PK_LinkedIn_tudors : LinkedIn
{
    meta:
        description = "Phishing Kit impersonating LinkedIn"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-26"
        comment = "Phishing Kit - LinkedIn - '<title>The Tudors</title>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "img"
        $spec_file1 = "0.png"
        $spec_file2 = "1.png"
        $spec_file3 = "hello.php"
        $spec_file4 = "block_detectors.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and 
        // check for files
        all of ($spec_file*)
}
