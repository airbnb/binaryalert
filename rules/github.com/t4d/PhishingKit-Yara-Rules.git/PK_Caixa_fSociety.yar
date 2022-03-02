rule PK_Caixa_fSociety : Caixa
{
    meta:
        description = "Phishing Kit impersonating Caixa Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://stalkphish.com/2020/12/14/how-phishing-kits-use-telegram/"
        date = "2021-10-11"
        comment = "Phishing Kit - Caixa Bank - 'By fSOCIETY'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "system"
        $spec_file1 = "Confirams.php"
        $spec_file2 = "TelegramApi.php"
        $spec_file3 = "system.php"
        $spec_file4 = "send_carde.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}