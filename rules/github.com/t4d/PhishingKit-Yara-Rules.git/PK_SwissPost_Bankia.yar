rule PK_SwissPost_Bankia : SwissPost
{
    meta:
        description = "Phishing Kit impersonating Swiss Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-20"
        comment = "Phishing Kit - Swiss Post - by 'Adem'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "BANKIA_files"
        // specific file found in PhishingKit
        $spec_file = "2038_logo.gif"
        $spec_file2 = "pwdbaseud.js.download"
        $spec_file3 = "sms/id.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        $spec_dir
}