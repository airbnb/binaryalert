rule PK_Chase_Xbalti : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-12-29"
        comment = "Phishing Kit - Chase Bank - XBalti"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "XBALTI"
        // specific files found in PhishingKit
        $spec_file = "chasefavicon.ico"
        $spec_file2 = "Email.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   $spec_file and 
	   $spec_file2 
}