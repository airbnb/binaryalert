rule PK_Banque_Populaire : Banque Populaire
{
    meta:
        description = "Phishing Kit impersonating Banque Populaire"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-12-28"
        comment = "Phishing kit impersonating Banque Populaire"        

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        $spec_file = "BP_Picto_service-securise.png"
        $spec_file2 = "play_cyberplus.svg" nocase

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
