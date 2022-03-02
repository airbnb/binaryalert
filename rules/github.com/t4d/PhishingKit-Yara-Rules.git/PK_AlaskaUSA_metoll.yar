rule PK_AlaskaUSA_metoll : AlaskaUSA
{
    meta:
        description = "Phishing Kit impersonating Alaska USA Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-22"
        comment = "Phishing Kit - AlaskaUSA - '-+ MeToll +-'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific files found in PhishingKit
        $spec_file = "1.php"
        $spec_file2 = "2.php"
        $spec_file3 = "security.php"
        $spec_file4 = "AkusaIcon.ttf"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}
