rule PK_TrustWallet_it : TrustWallet
{
    meta:
        description = "Phishing Kit impersonating Trust Wallet"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-22"
        comment = "Phishing Kit - Trust Wallet - 'From:Trust W | IT <webmail@'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "trust"
        // specific file found in PhishingKit
        $spec_file = "trust_logotype.svg"
        $spec_file2 = "CrYpTo.php"
        $spec_file3 = "recovery.php"
        $spec_file4 = "pattern.php"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}
