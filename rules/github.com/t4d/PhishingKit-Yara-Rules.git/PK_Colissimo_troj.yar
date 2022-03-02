rule PK_Colissimo_troj : Colissimo
{
    meta:
        description = "Phishing Kit impersonating Colissimo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-11-05"
        comment = "Phishing Kit - Colissimo - 'From: KHALISS ~<Troj>'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "off"
        // specific files found in PhishingKit
        $spec_file = "data.php"
        $spec_file1 = "bot.php"
        $spec_file2 = "verification-error.html"
        $spec_file3 = "envoi-colissimo.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}