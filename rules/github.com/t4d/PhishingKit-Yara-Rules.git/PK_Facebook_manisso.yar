rule PK_Facebook_manisso : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://github.com/Manisso"
        date = "2021-01-10"
        comment = "Phishing Kit - Facebook - 'By Manisso'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "login.php"
        $spec_file2 = "fb.php"
        $spec_file3 = "robots.txt"
        $spec_file4 = ".htaccess"
        $spec_file5 = "finish.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}

