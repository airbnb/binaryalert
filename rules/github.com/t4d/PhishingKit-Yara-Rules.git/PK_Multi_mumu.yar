rule PK_Multi_mumu
{
    meta:
        description = "Phishing Kit impersonating Several brands (hotmail, hanmail, 163, AE, ...)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-31"
        comment = "Phishing Kit - Multiple - found mailing-list called mumu*.txt"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "image"
        // specific file found in PhishingKit
        $spec_file = "process.php"
        $spec_file2 = "naver.php"
        $spec_file3 = "rediff.php"
	    $spec_file4 = "sp_btn_20140615.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_dir and 
        all of ($spec_file*)
}

