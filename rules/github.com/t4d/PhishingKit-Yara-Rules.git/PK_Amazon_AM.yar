rule PK_Amazon_AM : Amazon
{
    meta:
        description = "Phishing Kit impersonating Amazon.fr"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-24"
        comment = "Phishing Kit - Amazon.fr - based on a Ameli.fr phishing kit"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "classes"
        $spec_file1 = "savesms.php"
        $spec_file2 = "saveccs.php"
        $spec_file3 = "informations_verif_2.php"
        $spec_file4 = "check_cc.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}