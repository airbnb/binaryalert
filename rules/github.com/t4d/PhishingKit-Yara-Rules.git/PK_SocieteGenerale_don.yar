rule PK_SocieteGenerale_don : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-09-01"
        comment = "Phishing Kit - Societe Generale - 'From:  Tel <don@mox.fr>'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "index_files"
        $spec_file1 = "sms.html"
        $spec_file2 = "send2.php"
        $spec_file3 = "red.php"
        $spec_file4 = "funcs.php"
        $spec_file5 = "tel.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}