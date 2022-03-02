rule PK_ATT_jeff : ATandT
{
    meta:
        description = "Phishing Kit impersonating ATandT"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-16"
        comment = "Phishing Kit - ATandT - using jeff_.php files"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "jeff3.php"
        $spec_file2 = "jeff2.php"
        $spec_file3 = "jeff.php"
        $spec_file4 = "index4.php"

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