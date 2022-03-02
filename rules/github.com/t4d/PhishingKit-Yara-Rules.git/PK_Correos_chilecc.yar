rule PK_Correos_chileccc : Correos
{
    meta:
        description = "Phishing Kit impersonating Correos de Costa Rica"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-03"
        comment = "Phishing Kit - Correos - 'CHILE CC :)'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Autentisering_files"
        $spec_file1 = "auth2.php"
        $spec_file2 = "zlatan.php"
        $spec_file3 = "loader.gif"
        $spec_file4 = "ipv4.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}