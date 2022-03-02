rule PK_OneDrive_osbr : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-07-25"
        comment = "Phishing Kit - OneDrive - 'create an new instant of OS_BR class'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        // specific file found in PhishingKit
        $spec_file = "mail.php"
        $spec_file2 = "sync.php"
        $spec_file3 = "drive.php"
	    $spec_file4 = "0.jpg"
        $spec_file5 = "1.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_dir and 
        all of ($spec_file*)
}