rule PK_CIBC_franco : CIBC
{
    meta:
        description = "Phishing Kit impersonating Canadian Imperial Bank of Commerce"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-06-27"
        comment = "Phishing Kit - CIBC - 'CREATED BY FRANCOBOY'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "favicons"
        // specific files found in PhishingKit
        $spec_file2 = "index.html"
        $spec_file3 = "bannernext.php"
        $spec_file4 = "SignOn.cibc.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}