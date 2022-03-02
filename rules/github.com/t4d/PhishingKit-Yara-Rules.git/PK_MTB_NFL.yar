rule PK_MTB_NFL : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-28"
        comment = "Phishing Kit - M&T Bank - 'From:  NFL <demoi@r1z.com>'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "mtbonline"
        // specific files found in PhishingKit
        $spec_file = "drey.php"
        $spec_file2 = "index.htm"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        $spec_file and
        $spec_file2 
}
