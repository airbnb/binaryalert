rule PK_DEWA_moha : DEWA
{
    meta:
        description = "Phishing Kit impersonating Dubai Electricity and Water Authority"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://stalkphish.com/2022/02/04/phishing-kit-moha-kit-targeting-dewa-suppliers/"
        date = "2022-02-03"
        comment = "Phishing Kit - DEWA - '- Created By Moha404 +'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Login"
        $spec_dir2 = "moha404"
        $spec_file1 = "The-blacklist.php"
        $spec_file2 = "dewalogo2x.png"
        $spec_file3 = "zayan.php"
        $spec_file4 = "hamza.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
