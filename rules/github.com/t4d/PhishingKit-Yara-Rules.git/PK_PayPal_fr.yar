rule PK_PayPal_fr : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-06-11"
        comment = "Phishing Kit - PayPal - write in french, exfil fields too"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "doc"
        // specific files found in PhishingKit
        $spec_file1 = "snddta.php"
        $spec_file2 = "updtprf.php"
        $spec_file3 = "updt_ident.php"
        $spec_file4 = "flowHFR.css"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and 
        all of ($spec_file*)
}