rule PK_Orange_Banderas : Orange
{
    meta:
        description = "Phishing Kit impersonating Orange"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-17"
        comment = "Phishing Kit - Orange - 'by lapino banderas'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "BANDERAS"
        // specific file found in PhishingKit
        $spec_file = "report.php"
        $spec_file2 = "desktop.php"
        $spec_file3 = "thanks.php"
	    $spec_file4 = "vbv.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4 and
	    $spec_dir
}

