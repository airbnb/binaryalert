rule PK_AlaskaUSA_h4 : AlaskaUSA
{
    meta:
        description = "Phishing Kit impersonating Die Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-12-29"
        comment = "Phishing Kit - AlaskaUSA - '-Emp0w3r3d By Mr.H4-'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "ak"
        $spec_file1 = "index.htm"
        $spec_file2 = "verify.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*) and
        filesize < 5KB
}
