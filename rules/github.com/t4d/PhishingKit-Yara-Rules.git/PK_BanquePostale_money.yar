rule PK_BanquePostale_money : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-12"
        comment = "Phishing kit - Banque Postale - 'From: <noreply@money.cj>'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "config"
        $spec_dir1 = "data"
        // specific file found in PhishingKit
        $spec_file = "trans.php"
        $spec_file2 = "funcs.php"
        $spec_file3 = "settings.php"
        $spec_file4 = "cle-digitale.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}