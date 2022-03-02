rule PK_FreeMobile_ghaz : FreeMobile_ghaz
{
    meta:
        description = "Phishing Kit impersonating FreeMobile"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-12-28"
        comment = "Phishing kit impersonating FreeMobile - 'ghaz' version"  

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        $spec_file = "ghaz.php"
        $spec_dir = "freemobile" nocase

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $local_file and
        // check for file
        $spec_file and
        // check for directory
        $spec_dir
}
