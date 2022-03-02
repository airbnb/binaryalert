rule PK_YahooMail_Mobs : YahooMail
{
    meta:
        description = "Phishing Kit impersonating Yahoo Mail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-01"
        comment = "Phishing Kit - Yahoo Mail - 'Created By MOBS'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "yahoo"
        // specific file found in PhishingKit
        $spec_file = "logindetails.php"
        $spec_file2 = "yahoo.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_dir
}