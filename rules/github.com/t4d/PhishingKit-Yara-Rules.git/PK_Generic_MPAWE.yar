rule PK_Generic_MPAWE : Mpawe_Generic
{
    meta:
        description = "Phishing Kit - MPawe"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2019-12-13"
        comment = "Phishing Kit - MPawe"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "mpaweskd" nocase
        $spec_file2 = "jwqop.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2
}

