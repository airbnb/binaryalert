rule PK_Caixa_vbv : Caixa
{
    meta:
        description = "Phishing Kit impersonating Caixa Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://stalkphish.com/2020/12/14/how-phishing-kits-use-telegram/"
        date = "2022-01-22"
        comment = "Phishing Kit - Caixa Bank - 'caixa-vbvfinal' - exfil via Telegram"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "imatge"
        $spec_file1 = "Tarjeta2.html"
        $spec_file2 = "candado.png"
        $spec_file3 = "call911.php"
        $spec_file4 = "DataPost.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
