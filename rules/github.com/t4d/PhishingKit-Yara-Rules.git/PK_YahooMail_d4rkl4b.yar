rule PK_YahooMail_d4rkl4b : YahooMail
{
    meta:
        description = "Phishing Kit impersonating Yahoo Mail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-25"
        comment = "Phishing Kit - Yahoo Mail - 'D4rkL4B'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "thanks2017.html"
        $spec_file2 = "comp.php"
        $spec_file3 = "render.gif"
        $spec_file4 = "yahoo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}