rule PK_Facebook_tigari : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-29"
        comment = "Phishing Kit - Facebook - 'file_put_contents tigari.txt'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "sign_in_files"
        // specific file found in PhishingKit
        $spec_file = "finishlogin.php"
        $spec_file2 = "gateway.php"
        $spec_file3 = "sign_in.html"
        $spec_file4 = "newlogo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}

