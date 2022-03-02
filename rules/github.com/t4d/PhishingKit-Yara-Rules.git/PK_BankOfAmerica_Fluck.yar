rule PK_BankOfAmerica_Fluck : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-10"
        comment = "Phishing Kit - BankOfAmerica - by 'Flow'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "_+_1=ie_+.htm"
        $spec_file2 = "_+--++-=.php"
        $spec_file3 = "-=-----+++++_.php"
        $spec_file4 = "=-_+=.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}

