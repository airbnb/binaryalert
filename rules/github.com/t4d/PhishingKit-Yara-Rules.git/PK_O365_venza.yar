rule PK_O365_venza : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-28"
        comment = "Phishing Kit - Office 365 - 'CrEaTeD bY VeNzA'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir1 = "images"
        $spec_file1 = "email.php"
        $spec_file2 = "next.php"
        $spec_file3 = "bg.jpg"
        $spec_file4 = "index.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}