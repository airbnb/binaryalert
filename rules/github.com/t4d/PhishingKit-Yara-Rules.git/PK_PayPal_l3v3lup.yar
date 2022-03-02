rule PK_PayPal_l3v3lup : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-31"
        comment = "Phishing Kit - Paypal - 'By L3V3L UP'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "get_started"
        // specific file found in PhishingKit
        $spec_file = "iswrong.php"
        $spec_file2 = "fake_result.php"
        $spec_file3 = "js-plus.js"
	    $spec_file4 = "vbv.php"

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