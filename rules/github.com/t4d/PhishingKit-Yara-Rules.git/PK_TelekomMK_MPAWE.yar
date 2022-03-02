rule PK_TelekomMK_MPAWE : Telekom_MK
{
    meta:
        description = "Phishing Kit impersonating Telekom MK"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2019-12-13"
        comment = "Phishing Kit - Telekom MK - MPawe"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "mpaweskd" nocase
        $spec_file2 = "jwqop.jpg"
        $spec_file3 = "thomemk.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3
}

