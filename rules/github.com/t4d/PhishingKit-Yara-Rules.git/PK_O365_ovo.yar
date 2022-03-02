rule PK_O365_ovo : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-08-29"
        comment = "Phishing Kit - Office 365 - '+ Created by OVO-360+'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "n.php"
        $spec_file2 = "index.html"
        $spec_file3 = "ind.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}