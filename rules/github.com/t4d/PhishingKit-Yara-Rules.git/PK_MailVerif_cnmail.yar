rule PK_MailVerif_cnmail : MailVerif
{
    meta:
        description = "Phishing Kit harvesting e-mail addresses passwords"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-02"
        comment = "Phishing Kit - MailVerif - '$domain=cnmail'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "files"
        // specific file found in PhishingKit
        $spec_file = "x3d.php"
        $spec_file2 = "boxMrenewal.php"
        $spec_file3 = "boxMe.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_dir
}