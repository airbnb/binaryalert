rule PK_impots_gouv_fr_azubi : impots_gouv_fr
{
    meta:
        description = "Phishing Kit impersonating impots.gouv.fr"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-06-12"
        comment = "Phishing Kit - impots.gouv.fr - 'YOUR WELCOME AZUBI'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "templates"
        $spec_file1 = "post.php"
        $spec_file2 = "impots_gouv_fr_header-Sans fond.svg"
        $spec_file3 = "Logo-Marianne_impots-gouv-fr.svg"
        $spec_file4 = "snd3.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}