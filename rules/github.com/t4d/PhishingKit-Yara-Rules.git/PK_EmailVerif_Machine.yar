rule PK_EmailVerif_Machine : Email_verification
{
    meta:
        description = "Phishing Kit stealing email credentials"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-25"
        comment = "Phishing Kit - Email Verification - 'Scripted by Machine'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "deactivation"
        // specific file found in PhishingKit
        $spec_file = "Message.txt"
        $spec_file2 = "appstore.jpg"
        $spec_file3 = "googleplay.png"
        $spec_file4 = "error.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
	    $spec_file4
}

