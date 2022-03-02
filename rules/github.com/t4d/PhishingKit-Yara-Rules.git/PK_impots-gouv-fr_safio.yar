rule PK_impots_gouv_fr_safio : impots_gouv_fr
{
    meta:
        description = "Phishing Kit impersonating impots.gouv.fr"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-06-10"
        comment = "Phishing Kit - impots.gouv.fr - 'Created BY Safio TeaM'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "error/X"
        $spec_file1 = "Cobra.php"
        $spec_file2 = "aide.gif"
        $spec_file3 = "bastila.PNG"
        $spec_file4 = "puce_lien_liste_serv_dgfip.gif"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}