rule PK_1and1_Ionos : one_and_one
{
    meta:
        description = "Phishing Kit impersonating IONOS by 1and1"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-02"
        comment = "Phishing Kit - 1and1"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "1&1 IONOS E-Mail login_files"
        // specific file found in PhishingKit
        $spec_file = "1and1.php"
        $spec_file2 = "1&1 IONOS E-Mail login.html"
        $spec_file3 = "ionos.min.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3
}

