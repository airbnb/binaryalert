rule PK_Absa_oreoo : Absa
{
    meta:
        description = "Phishing Kit impersonating Absa"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-19"
        comment = "Phishing Kit - Absa Online - 'CREATED BY Walid Nabil (OREOO)'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "registration"
        // specific file found in PhishingKit
        $spec_file = "BOT_12.php"
        $spec_file2 = "App/absa.css"
        $spec_file3 = "YOUR_EMAIL.php"
        $spec_file4 = "send_ConfirmApp.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}