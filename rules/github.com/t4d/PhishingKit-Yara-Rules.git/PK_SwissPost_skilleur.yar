rule PK_SwissPost_skilleur : SwissPost
{
    meta:
        description = "Phishing Kit impersonating Swiss Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-11-01"
        comment = "Phishing Kit - Swiss Post - by '>SKILLEUR<'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "wait"
        // specific file found in PhishingKit
        $spec_file = "Done.html"
        $spec_file2 = "smserror.php"
        $spec_file3 = "0035.png"
        $spec_file4 = "lmo.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        $spec_dir
}