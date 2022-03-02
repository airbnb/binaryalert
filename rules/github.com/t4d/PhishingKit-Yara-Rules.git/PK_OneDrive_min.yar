rule PK_OneDrive_min : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-27"
        comment = "Phishing Kit - OneDrive - a minimalistic phishing kit"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "custom"
        // specific file found in PhishingKit
        $spec_file = "onedrive.png"
        $spec_file2 = "header.php"
        $spec_file3 = "footer.php"
	    $spec_file4 = "investment-portfolio.pdf"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_dir and 
        all of ($spec_file*)
}

