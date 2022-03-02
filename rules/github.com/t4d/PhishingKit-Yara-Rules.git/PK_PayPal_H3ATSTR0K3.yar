rule PK_PayPal_H3ATSTR0K3 : PayPal
{
    meta:
        description = "Phishing Kit impersonating PayPal"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2019-11-28"
        comment = "Phishing Kit - PayPal - H3ATSTR0K3"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "prevents"
        // specific file found in PhishingKit
        $spec_file = "mine.php" nocase
        $spec_file2 = "bcce592108d8ec029aa75f951662de2e.jpeg"
        $spec_file3 = "captured.txt"
        $spec_file4 = "H3ATSTR0K3.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4 and
        // check for directory
        $spec_dir
}

