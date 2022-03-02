rule PK_NatWest_kts : NatWest
{
    meta:
        description = "Phishing Kit impersonating NatWest bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-20"
        comment = "Phishing Kit - NatWest - 'page made by KTS team'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "safeguard"
        // specific file found in PhishingKit
        $spec_file = "php.php"
        $spec_file2 = "man.txt"
        $spec_file3 = "cloaker.php"
        $spec_file4 = "sign.sh"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}