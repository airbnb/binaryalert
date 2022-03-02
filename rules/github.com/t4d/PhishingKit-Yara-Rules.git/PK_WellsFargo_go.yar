rule PK_WellsFargo_go : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-09-20"
        comment = "Phishing Kit - Wells Fargo - using several 'go' files"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "go_files"
        // specific file found in PhishingKit
        $spec_file = "go.htm"
        $spec_file2 = "go.php"
        $spec_file3 = "login-userprefs.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
