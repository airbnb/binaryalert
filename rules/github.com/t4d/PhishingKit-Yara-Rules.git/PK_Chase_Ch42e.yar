rule PK_Chase_Ch42e : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-25"
        comment = "Phishing Kit - Chase Bank - From: customer@Ch42e.org"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "ip_files"
        // specific files found in PhishingKit
        $spec_file = "process4.php"
        $spec_file2 = "emaila.php"
        $spec_file3 = "acct.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   $spec_dir and 
	   $spec_file and 
	   $spec_file2 and
       $spec_file3
}