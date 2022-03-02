rule PK_EarthLink_33flow : EarthLink
{
    meta:
        description = "Phishing Kit impersonating EarthLink"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-22"
        comment = "Phishing Kit - EarthLink - 'Created in 2020 [ Don  33flow ]'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "imgs"
        // specific file found in PhishingKit
        $spec_file = "delete.php"
        $spec_file2 = "_+--_=_.php"
        $spec_file3 = "elnk_logo.png"
        $spec_file4 = "_=+---+_=.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}