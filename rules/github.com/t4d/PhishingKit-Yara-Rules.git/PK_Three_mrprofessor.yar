rule PK_Three_mrprofessor : Three
{
    meta:
        description = "Phishing Kit impersonating Three.co.uk"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-21"
        comment = "Phishing Kit - Three - 'Scampage by MrProfessor'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "My3Login_data"
        // specific file found in PhishingKit
        $spec_file = "fg.php"
        $spec_file2 = "lg.php"
        $spec_file3 = "CONTROLS.php"
        $spec_file4 = "My3Login.html"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}