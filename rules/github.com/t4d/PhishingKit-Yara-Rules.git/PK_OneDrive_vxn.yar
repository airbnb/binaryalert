rule PK_OneDrive_vxn : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-27"
        comment = "Phishing Kit - OneDrive - 'From: VXN@$hostname'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "home"
        // specific file found in PhishingKit
        $spec_file = "index_offpass_invalid.php"
        $spec_file2 = "index_otherinvalid.php"
        $spec_file3 = "vxn_off.php"
	    $spec_file4 = "vxn_other_invalid.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_dir and 
        all of ($spec_file*)
}

