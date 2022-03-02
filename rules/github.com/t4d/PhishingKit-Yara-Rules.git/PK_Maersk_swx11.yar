rule PK_Maersk_swx11 : Maersk
{
    meta:
        description = "Phishing Kit impersonating Maersk"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-07"
        comment = "Phishing Kit - Maersk - use a file named 'Maerskswx11.txt'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        // specific file found in PhishingKit
        $spec_file = "maer.php"
        $spec_file2 = "dala.php"
        $spec_file3 = "b6.jpg"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}

