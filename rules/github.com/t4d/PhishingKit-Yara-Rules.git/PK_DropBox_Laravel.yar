rule PK_DropBox_Laravel : Dropbox
{
    meta:
        description = "Phishing Kit impersonating DropBox"
        licence = ""
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-12-28"
        comment = "Phishing Kit - DropBox - Laravel with admin module"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "administrator"
        // specific files found in PhishingKit
        $spec_file = "serverbusy.php"
        $spec_file2 = "database.php"
        $spec_file3 = "bts.php"

    condition:
        // look for the ZIP header and all
        uint32(0) == 0x04034b50 and $local_file and $spec_dir and $spec_file and $spec_file2 and $spec_file3
}
