rule PK_1and1_Ionos_mademen : one_and_one
{
    meta:
        description = "Phishing Kit impersonating IONOS by 1and1"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-13"
        comment = "Phishing Kit - IONOS - 'MADEMEN CYBER TEAM'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "demo_files"
        // specific file found in PhishingKit
        $spec_file = "demp.php"
        $spec_file2 = "go.php"
        $spec_file3 = "err.php"
        $spec_file4 = "load.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}