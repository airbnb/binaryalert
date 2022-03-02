rule PK_Chase_spox : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://blog.sucuri.net/2020/07/spox-phishing-kit-harvests-chase-bank-credentials.html"
        date = "2021-05-05"
        comment = "Phishing Kit - Chase Bank - 'C0d3d by Spox_dz'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Spox"
        // specific files found in PhishingKit
        $spec_file = "YOUR-CONFIG.php"
        $spec_file2 = "Bot-Spox.php"
        $spec_file3 = "chasefavicon.ico"
        $spec_file4 = "Fuck-you.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}