rule PK_French_Impots : impots_FR
{
    meta:
        description = "Phishing Kit impersonating French taxes portal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-12-28"
        comment = "Phishing Kit - French_impots - French taxes portal"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        $spec_file = "remboursement.html"
        $spec_file2 = "impots_gouv_fr_header-Sans fond.svg" nocase

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $local_file and
        // check for file
        $spec_file and
        // check for directory
        $spec_file2
}
