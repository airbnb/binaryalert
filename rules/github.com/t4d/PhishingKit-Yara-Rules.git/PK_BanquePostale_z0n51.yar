rule PK_BanquePostale_z0n51 : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-26"
        comment = "Phishing kit - Banque Postale - 'Author: z0n51'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "php-credit-card-validator"
        $spec_dir1 = "login"
        // specific file found in PhishingKit
        $spec_file = "submit.php"
        $spec_file2 = "botadmin.php"
        $spec_file3 = "functions.php"
        $spec_file4 = "certicode.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}