rule PK_BBVA_AR : BBVA
{
    meta:
        description = "Phishing Kit impersonating BBVA Argentina"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-25"
        comment = "Phishing Kit - BBVA - 'BBVA Argentina'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "contacto"
        $spec_file1 = "phperro.php"
        $spec_file2 = "LogonOperacionServlet.html"
        $spec_file3 = "phpbbva2.php"
        $spec_file4 = "phperrof.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
