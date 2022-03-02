rule PK_EIM_westgirl : Etisalat
{
    meta:
        description = "Phishing Kit impersonating Etisalat Internet Mail (EIM)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-19"
        comment = "Phishing Kit - Etisalat - 'WeStGiRl'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "login_files"
        // specific file found in PhishingKit
        $spec_file = "login.htm"
        $spec_file2 = "dojo.js"
        $spec_file3 = "west.php"
        $spec_file4 = "a.htm"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}