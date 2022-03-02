rule PK_Rackspace_Metoll : Rackspace
{
    meta:
        description = "Phishing Kit impersonating Rackspace"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-10-22"
        comment = "Phishing Kit - Rackspace - '+ MeToll +'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "image"
        // specific file found in PhishingKit
        $spec_file = "jfk.php"
        $spec_file2 = "rracspc.html"
        $spec_file3 = "c3.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        $spec_dir
}