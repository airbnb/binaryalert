rule PK_PayPal_ShadowZ118 : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-01"
        comment = "Phishing Kit - Paypal - Shadow Z118 v1.10 - scam Paypal"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "functions"
        // specific file found in PhishingKit
        $spec_file = "FULLZ_CARD.php"
        $spec_file2 = "V-Z118.js"
        $spec_file3 = "14303695_853354554765349_388275294_o.jpg"
	    $spec_file4 = "badge-512.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4 and
	    $spec_dir
}

