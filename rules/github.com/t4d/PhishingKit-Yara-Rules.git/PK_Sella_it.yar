rule PK_Sella_it : Sella
{
    meta:
        description = "Phishing Kit impersonating Banca Sella"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-12-03"
        comment = "Phishing Kit - Banca Sella S.p.A."

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "pannello"
        $spec_file1 = "errore.php"
        $spec_file2 = "datistat.php"
        $spec_file3 = "suono.wav"
        $spec_file4 = "statistiche.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
