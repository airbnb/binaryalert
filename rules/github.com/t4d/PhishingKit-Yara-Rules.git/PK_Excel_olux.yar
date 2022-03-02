rule PK_Excel_olux : Excel
{
    meta:
        description = "Phishing Kit impersonating Excel page"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-07"
        comment = "Phishing Kit - Excel - by 'ICQ:724691041 (olux)'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "wait.php"
        $spec_file2 = "bizmail.php"
        $spec_file3 = "remove.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3
	//$spec_dir
}

