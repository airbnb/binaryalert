rule PK_Ebay_Ghost : EBay
{
    meta:
        description = "Phishing Kit impersonating Ebay"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-04"
        comment = "Phishing Kit - EBay - '---|Ghost Rider|---'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        // specific file found in PhishingKit
        $spec_file = "34wtddjp0q1v1dtu2elv5jwg4yf.css"
        $spec_file2 = "geoplugin.class.php"
        $spec_file3 = "data.php"
        $spec_file4 = "Login.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
	    $spec_file4
}