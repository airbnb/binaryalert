rule PK_CIBC_xb1yydex : CIBC
{
    meta:
        description = "Phishing Kit impersonating Canadian Imperial Bank of Commerce"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-26"
        comment = "Phishing Kit - CIBC - 'in /home/xb1yydex/public_html/Cibc.ca/'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "bank_files"
        // specific files found in PhishingKit
        $spec_file = "da.php"
        $spec_file2 = "xxx.php"
        $spec_file3 = "complete-CIBC.html"
        $spec_file4 = "index11.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   all of ($spec_file*)
}