rule PK_DocuSign_zoom : DocuSign
{
    meta:
        description = "Phishing Kit impersonating DocuSign"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-20"
        comment = "Phishing Kit - DocuSign - 'ZOOM (.) RU WhatsApp +CEO'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "ss_files"
        $spec_file1 = "aa.php"
        $spec_file2 = "otdc.php"
        $spec_file3 = "geoplugin.class.php"
        $spec_file4 = "verification.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
