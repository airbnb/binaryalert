rule PK_HSBC_payee : HSBC
{
    meta:
        description = "Phishing Kit impersonating HSBC"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-29"
        comment = "Phishing Kit - HSBC - deployed on many domains containing 'payee' string"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "admin"
        $spec_dir2 = "security.hsbc"
        $spec_file1 = "rec.php"
        $spec_file2 = "installerdb.php"
        $spec_file3 = "idv.PayeeReq.php"
        $spec_file4 = "idv.Verifying.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
