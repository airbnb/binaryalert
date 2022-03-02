rule PK_WhatsApp_Group_Invite_Berbagi : WhatsApp
{
    meta:
        description = "Phishing Kit impersonating WhatsApp"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-11-28"
        comment = "Phishing Kit - WhatsApp group invite - Berbagi"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "pastel"
        // specific file found in PhishingKit
        $spec_file = "snd2.php" nocase

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $local_file and
        // check for file
        $spec_file and
        // check for directory
        $spec_dir
}
