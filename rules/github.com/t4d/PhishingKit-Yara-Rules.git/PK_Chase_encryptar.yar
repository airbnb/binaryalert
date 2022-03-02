rule PK_Chase_encryptar : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-01"
        comment = "Phishing Kit - Chase Bank - 'require_once encriptar.php'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        // specific files found in PhishingKit
        $spec_file = "encriptar.php"
        $spec_file2 = "mailer.php"
        $spec_file3 = "action.php"
        $spec_file4 = "Finish.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   $spec_file and 
	   $spec_file2 and
       $spec_file3 and
       $spec_file4
}