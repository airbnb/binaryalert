rule PK_PayPal_AK47_666 : PayPal
{
    meta:
        description = "Phishing Kit impersonating PayPal"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = "https://thequickredfox.ca/2020/01/05/walkthrough-of-the-ppl-v7-paypal-phishing-kit/"
        date = "2021-01-21"
        comment = "Phishing Kit - PayPal - 'AK47-VbV' version '666'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "proof"
        // specific file found in PhishingKit
        $spec_file = "algo.php"
        $spec_file2 = "bank.php"
        $spec_file3 = "identity.php"
        $spec_file4 = "mailprovider.php"
        $spec_file5 = "signin.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}