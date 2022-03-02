rule PK_SocieteGenerale_bddf : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-22"
        comment = "Phishing Kit - Societe Generale - 'firm: BDDF'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "javascript"
        $spec_file1 = "savesms.php"
        $spec_file2 = "phone_2.php"
        $spec_file3 = "informations_verif_2.php"
        $spec_file4 = "ooljquery.cryxpad.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}

