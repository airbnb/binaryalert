rule PK_Generic_RD337 : RD337_Generic
{
    meta:
        description = "Phishing Kit - RD337 - Generic email credentials stealer"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-01-29"
        comment = "Phishing Kit - RD337"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        // specific file found in PhishingKit
        $spec_file = "26-269507_arbys-logo-transparent-norton-secured-logo-png-png.png"
        $spec_file2 = "next.php"
        $spec_file3 = "email.php"
        $spec_file4 = "favicons"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}

