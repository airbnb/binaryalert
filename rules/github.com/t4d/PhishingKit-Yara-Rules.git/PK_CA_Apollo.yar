rule PK_CA_Apollo : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-03"
        comment = "Phishing Kit - Credit Agricole - '_____APOLLO_____'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "block"
        $spec_file1 = "index.js"
        $spec_file2 = "ilogo.svg"
        $spec_file3 = "fake.php"
        $spec_file4 = "settings.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}