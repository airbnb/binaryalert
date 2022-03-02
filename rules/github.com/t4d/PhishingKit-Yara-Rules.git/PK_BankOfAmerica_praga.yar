rule PK_BECU_praga : BECU
{
    meta:
        description = "Phishing Kit impersonating BECU bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-03"
        comment = "Phishing Kit - BECU - '&id=$praga$praga'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        // specific file found in PhishingKit
        $spec_file = "next2.php"
        $spec_file2 = "step3.php"
        $spec_file3 = "btn2.png"

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

