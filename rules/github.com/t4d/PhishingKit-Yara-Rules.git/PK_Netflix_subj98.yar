rule PK_Netflix_subj98 : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-02"
        comment = "Phishing Kit - Netflix - '$subj98'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "BOTS"
        $spec_dir2 = "action"
        // specific file found in PhishingKit
        $spec_file = "loading_.php"
        $spec_file2 = "newips.php"
        $spec_file3 = "otp_error.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and 
        $spec_dir and 
        $spec_dir2
}