rule PK_XFinity_slim : XFinity
{
    meta:
        description = "Phishing Kit impersonating XFinity"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-13"
        comment = "Phishing Kit - XFinity - 'Created By SLim'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Sign in to XFINITY_files"
        $spec_file1 = "verify.php"
        $spec_file2 = "1647526060x32.js"
        $spec_file3 = "asc.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
