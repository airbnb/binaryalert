rule PK_DHL_Metri : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-24"
        comment = "Phishing Kit - DHL - 'Metri copyright'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "core"
        $spec_file1 = "email-dialk.php"
        $spec_file2 = "smssend.php"
        $spec_file3 = "user_agent.php"
        $spec_file4 = "roboto-font.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
