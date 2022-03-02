rule PK_ScotiaBank_medpage : ScotiaBank
{
    meta:
        description = "Phishing Kit impersonating Scotia bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-21"
        comment = "Phishing Kit - Scotia bank - 'created by medpage[679849675]'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "files"
        $spec_file1 = "logging.php"
        $spec_file2 = "processing.php"
        $spec_file3 = "indexxx.php"
        $spec_file4 = "AppMeasurement_Module_ActivityMap.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
