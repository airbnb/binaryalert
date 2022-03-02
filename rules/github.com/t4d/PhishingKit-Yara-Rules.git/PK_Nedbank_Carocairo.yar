rule PK_Nedbank_Carocairo : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-02"
        comment = "Phishing Kit - Nedbank - '//$to_email = carocairo25'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "control"
        $spec_dir2 = "Banking"
        // specific file found in PhishingKit
        $spec_file = "NedbankExperience.svg"
        $spec_file2 = "sendData.php"
        $spec_file3 = "dest5.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_dir and 
        $spec_dir2
}