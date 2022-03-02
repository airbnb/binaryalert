rule PK_DeutschePost_zabi : DeutschePost
{
    meta:
        description = "Phishing Kit impersonating DeutschePost"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-12"
        comment = "Phishing Kit - DeutschePost - '. $zabi .'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "manage"
        // specific file found in PhishingKit
        $spec_file = "card.php"
        $spec_file2 = "block3.php"
        $spec_file3 = "1.css"
        $spec_file4 = "proxyblock.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}