rule PK_Jenis_GhostMode : Jenis
{
    meta:
        description = "Phishing Kit impersonating Jeni's Icecream"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1468487303001694208"
        date = "2021-12-08"
        comment = "Phishing Kit - Jeni's - 'GhostMode'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "jenis_files"
        // specific files found in PhishingKit
        $spec_file = "jenis.png"
        $spec_file2 = "result.php"
        $spec_file3 = "jenis.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
