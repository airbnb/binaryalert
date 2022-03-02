rule PK_Netflix_Panda : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-02"
        comment = "Phishing Kit - Netflix - 'Panda'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "prevents"
        // specific file found in PhishingKit
        $spec_file = "log.txt"
        $spec_file2 = "results.html"
        $spec_file3 = "mine.php"
        $spec_file4 = "HOW_TO_EDIT_SCAMA.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
         all of ($spec_file*)
}