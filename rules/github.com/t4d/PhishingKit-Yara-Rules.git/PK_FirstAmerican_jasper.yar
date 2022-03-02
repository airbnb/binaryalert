rule PK_FirstAmerican_jasper : FirstAmerican
{
    meta:
        description = "Phishing Kit impersonating First American insurance"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-05-12"
        comment = "Phishing Kit - First American - '[FA] JaSpEr $ip'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "0.php"
        $spec_file2 = "Borrower's-details.php"
        $spec_file3 = "Borrower's-details.shtml"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}