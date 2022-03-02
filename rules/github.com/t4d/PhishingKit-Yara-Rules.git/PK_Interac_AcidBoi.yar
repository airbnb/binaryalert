rule PK_Interac_AcidBoi : interac
{
    meta:
        description = "Phishing Kit impersonating Interac, several payment systems"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-03"
        comment = "Phishing Kit - Interac - 'Created By AcidBoi'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "directing"
        $spec_file1 = "fave.png"
        $spec_file2 = "activityi.htm"
        $spec_file3 = "interac-jqm.css"
        $spec_file4 = "question.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}