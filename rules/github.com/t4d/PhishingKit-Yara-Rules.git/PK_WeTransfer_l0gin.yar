rule PK_WeTransfer_l0gin : WeTransfer
{
    meta:
        description = "Phishing Kit impersonating WeTransfer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-16"
        comment = "Phishing Kit - WeTransfer - use of filename l0gin.php"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "bg1.png"
        $spec_file2 = "l0gin.php"
        $spec_file3 = "l0gin2nd.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3
}

