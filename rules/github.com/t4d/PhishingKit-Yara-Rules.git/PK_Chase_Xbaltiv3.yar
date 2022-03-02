rule PK_Chase_Xbaltiv3 : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://stalkphish.com/2021/04/22/scammer_vs_scammer_backdoored_phishing_kit/"
        date = "2021-04-21"
        comment = "Phishing Kit - Chase Bank - XBalti V3"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "XBALTI"
        // specific files found in PhishingKit
        $spec_file = "desktopnight.jpeg"
        $spec_file2 = "lostyle.css"
        $spec_file3 = "Email.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}