rule PK_Chase_zipxnx : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-12-01"
        comment = "Phishing Kit - Chase Bank - 'POST zipxnx'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Chase1_files"
        // specific files found in PhishingKit
        $spec_file = "Chase1.html"
        $spec_file2 = "verify.php"
        $spec_file3 = "Chase2.html"
        $spec_file4 = "access.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}