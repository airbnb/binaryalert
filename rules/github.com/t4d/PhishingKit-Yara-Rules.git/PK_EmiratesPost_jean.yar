rule PK_EmiratesPost_jean : EmiratesPost
{
    meta:
        description = "Phishing Kit impersonating EmiratesPost"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-11-01"
        comment = "Phishing Kit - EmiratesPost - '$jean_email'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "jean"
        // specific file found in PhishingKit
        $spec_file = "JN8.txt"
        $spec_file2 = "simo.png"
        $spec_file3 = "911.php"
        $spec_file4 = "casa.php"

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

