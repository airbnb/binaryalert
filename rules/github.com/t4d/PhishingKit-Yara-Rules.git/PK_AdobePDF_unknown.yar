rule PK_AdobePDF_unknown : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF online"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-31"
        comment = "Phishing Kit - Adobe PDF Online - 'Created BY unknown'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "autoregpdf"
        // specific file found in PhishingKit
        $spec_file = "Use Method.txt"
        $spec_file2 = "iz.php"
        $spec_file3 = "index.php"

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