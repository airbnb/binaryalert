rule PK_AlaskaUSA_unlock : AlaskaUSA
{
    meta:
        description = "Phishing Kit impersonating Alaska USA Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-15"
        comment = "Phishing Kit - AlaskaUSA - use a directory called 'Unlockalaska'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Unlockalaska"
        // specific files found in PhishingKit
        $spec_file = "Alaska.htm"
        $spec_file2 = "sara.php"
        $spec_file3 = "mje.html"
        $spec_file4 = "AkusaIcon9f39.ttf"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}

