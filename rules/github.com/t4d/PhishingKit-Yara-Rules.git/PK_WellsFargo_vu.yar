rule PK_WellsFargo_vu : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-25"
        comment = "Phishing Kit - Wells Fargo - fopen vu.txt"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "home"
        // specific file found in PhishingKit
        $spec_file = "index.htm"
        $spec_file2 = "blocker.php"
        $spec_file3 = "site.php"
        $spec_file4 = "site.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4
}

