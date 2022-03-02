rule PK_OneDrive_venza : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-27"
        comment = "Phishing Kit - OneDrive - 'CrEaTeD bY VeNzA'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "email.php"
        $spec_file2 = "next.php"
        $spec_file3 = "1.png"
        $spec_file4 = "1.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}