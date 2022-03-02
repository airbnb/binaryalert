rule PK_IRS_sirus : ICS
{
    meta:
        description = "Phishing Kit impersonating International Card Services"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-12-29"
        comment = "Phishing Kit - ICS - contain DCI directorS"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "SCI"
        // specific files found in PhishingKit
        $spec_file1 = "pattern.php"
        $spec_file2 = "ic-panel.php"
        $spec_file3 = "eigen bericht.php"
        $spec_file4 = "sca_controle.php"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and 
        all of ($spec_file*)
}