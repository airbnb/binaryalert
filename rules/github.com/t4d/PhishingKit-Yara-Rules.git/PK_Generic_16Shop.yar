rule PK_Generic_16Shop
{
    meta:
        description = "16Shop Phishing Kit"
        licence = ""
        author = "Guido Denzler"
        reference = ""
        date = "2020-02-25"
        comment = "Phishing Kit - Generic - 16Shop"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "crawlerdetect.php"
        $spec_file2 = "server.ini"
        $spec_file3 = "lang.php"
        $spec_file4 = "antibot.ini"
        $spec_file5 = "antibot.php"
        $spec_file6 = "onetime.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file 
        and 4 of ($spec_file*)
}
