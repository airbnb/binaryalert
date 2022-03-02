rule PK_Chase_dudiix : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-30"
        comment = "Phishing Kit - Chase Bank - 'Chase Email By Dudiix'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "img"
        // specific files found in PhishingKit
        $spec_file = "card.php"
        $spec_file2 = "done.php"
        $spec_file3 = "updater.php"
        $spec_file4 = "checkmark.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}