rule PK_Facebook_GSheet : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://stalkphish.com/2021/04/09/phishing-kit-using-google-sheet-to-exfiltrate-stolen-data/"
        date = "2021-04-09"
        comment = "Phishing Kit - Facebook - this phishing kit use Google sheet for exfiltration"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_file1 = "validation-functions.js"
        $spec_file2 = "bootstrapValidator.min.js"
        $spec_file3 = "pic.png"
        $spec_file4 = "logo.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
