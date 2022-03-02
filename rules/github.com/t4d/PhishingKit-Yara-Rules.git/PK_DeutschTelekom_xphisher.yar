rule PK_DeutschTelekom_xphisher : DeutschTelekom
{
    meta:
        description = "Phishing Kit impersonating DeutschTelekom - T Online"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-28"
        comment = "Phishing Kit - DeutschTelekom - T Online - 'Coded By x-Phisher'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "btele"
        $spec_file1 = "de.php"
        $spec_file2 = "antibots.txt"
        $spec_file3 = "antibots3.php"
        $spec_file4 = "authenticator.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
