rule PK_SFR_don : SFR
{
    meta:
        description = "Phishing Kit impersonating SFR Mail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-05"
        comment = "Phishing Kit - SFR Mail - '-Coded by don-'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "SFRMailmail_files"
        // specific file found in PhishingKit
        $spec_file = "SFRMailmail.htm"
        $spec_file2 = "mire-sfr-mail.jpg"
        $spec_file3 = "HSFR_ec2-1.png"
        $spec_file4 = "style-responsive.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_file4
}