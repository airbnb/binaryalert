rule PK_Rackspace_wales : Rackspace
{
    meta:
        description = "Phishing Kit impersonating Rackspace"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-04"
        comment = "Phishing Kit - Rackspace - 'Created By wales'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "rackspaceauto"
        // specific file found in PhishingKit
        $spec_file = "index.php"
        $spec_file2 = "log.php"
        $spec_file3 = "login.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_dir
}