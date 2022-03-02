rule PK_MACU_H4 : MACU
{
    meta:
        description = "Phishing Kit impersonating Mountain America Credit Union (MACU)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-26"
        comment = "Phishing Kit - Email Verification - 'Emp0w3r3d By Mr.H4'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "MACU"
        // specific file found in PhishingKit
        $spec_file = "verify.php"
        $spec_file2 = "index.htm"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        $spec_file and
        $spec_file2
}

