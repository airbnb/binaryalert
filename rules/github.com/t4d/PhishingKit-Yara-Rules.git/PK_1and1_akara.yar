rule PK_1and1_akara : one_and_one
{
    meta:
        description = "Phishing Kit impersonating IONOS by 1and1"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-02-02"
        comment = "Phishing Kit - 1and1 - 'By Akara Nwamama'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Psalm91"
        $spec_dir2 = "looptrace"
        // specific file found in PhishingKit
        $spec_file = "onye.php"
        $spec_file2 = "ionos.min.css"
        $spec_file3 = "ball.php"
        $spec_file4 = "http_class.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}