rule PK_GlobalSources_teamdevil : GlobalSources
{
    meta:
        description = "Phishing Kit impersonating GlobalSources"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-13"
        comment = "Phishing Kit - GlobalSources - '+ Created By T3@M D3V!L icq 705047245 +'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "teamdevil.php"
        $spec_file2 = "favi.ico"
        $spec_file3 = "GSLOGO.PNG"
        $spec_file4 = "GSLOGIN_PROMO_PIC.JPG"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}