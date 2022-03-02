rule PK_ATT_j0n3z : ATandT
{
    meta:
        description = "Phishing Kit impersonating ATandT"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-09"
        comment = "Phishing Kit - ATandT - 'Created By j0n3z'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "proxyblock.php"
        $spec_file2 = "vti.php"
        $spec_file3 = "lg.html"
        $spec_file4 = "nyb2.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_file4
}