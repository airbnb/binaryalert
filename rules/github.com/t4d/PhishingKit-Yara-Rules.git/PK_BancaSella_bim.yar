rule PK_BancaSella_bim : Banca Sella
{
    meta:
        description = "Phishing Kit impersonating Banca Sella"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-23"
        comment = "Phishing kit impersonating Banca Sella - $_SESSION[bim]"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "pagamento"
        $spec_file = "succes1.php"
        $spec_file2 = "rm.php"
        $spec_file3 = "l3des.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}