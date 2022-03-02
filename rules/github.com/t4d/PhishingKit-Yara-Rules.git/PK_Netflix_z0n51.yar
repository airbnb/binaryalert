rule PK_Netflix_z0n51 : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-06-02"
        comment = "Phishing Kit - Netflix - z0n51 directory"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "inc"
        $spec_dir2 = "z0n51/"
        // specific file found in PhishingKit
        $spec_file = "fbbb.png"
        $spec_file2 = "ss.php"
        $spec_file3 = "details.php"
        $spec_file4 = "app.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}