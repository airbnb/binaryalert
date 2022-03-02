rule PK_Chase_oreooo : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-25"
        comment = "Phishing Kit - Chase Bank - 'THIS Page WAS CREATED BY Walid Nabil (OREOO)'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Home"
        // specific files found in PhishingKit
        $spec_file = "Checkpoint.php"
        $spec_file2 = "Congratulations.php"
        $spec_file3 = "Billing.php"
        $spec_file4 = "Alert.php"
        $spec_file5 = "OReoo.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}