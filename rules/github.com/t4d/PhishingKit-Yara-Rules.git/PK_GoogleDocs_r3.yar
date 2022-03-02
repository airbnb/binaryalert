rule PK_GoogleDocs_r3 : GoogleDocs
{
    meta:
        description = "Phishing Kit impersonating Google docs"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-26"
        comment = "Phishing Kit - Google Docs"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        // specific file found in PhishingKit
        $spec_file = "docmsg.htm"
        $spec_file2 = "mail.php"
        $spec_file3 = "GmailTransparent1.png"
        $spec_file4 = "R3WinLive1033.css"
        $spec_file5 = "checkmark.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}

