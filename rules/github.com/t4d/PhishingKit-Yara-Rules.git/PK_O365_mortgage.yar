rule PK_O365_mortgage: Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365 'Mortgage'"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-09-01"
        comment = "Phishing Kit - Office 365 - '<title>Office365 Mortgage Email and Password Authorization</title>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Mid America Mortgage Password Authorization_files"
        $spec_file1 = "Mid America Mortgage Password Authorization.html"
        $spec_file3 = "americamortgage.php"
        $spec_file4 = "Error.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
