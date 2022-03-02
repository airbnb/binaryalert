rule PK_O365_codespirit : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-13"
        comment = "Phishing Kit - O365 - 'Created in CODE~SPIRIT'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific files found in PhishingKit
        $spec_file = "ind.php"
        $spec_file2 = "rst.htm"
        $spec_file3 = "index.html"
        $spec_file4 = "n.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}