rule PK_SocieteGenerale_sbou : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-02-02"
        comment = "Phishing Kit - Societe Generale - 'SG 2017 by Marco Sbou'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "AntiBoot"
        $spec_file1 = "logo-sg-seul.svg"
        $spec_file2 = "filter.php"
        $spec_file3 = "load1.html"
        $spec_file4 = "pass.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}