rule PK_O365_mex06 : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-12-03"
        comment = "Phishing Kit - O365 - all pictures/referers from mex06.emailsrvr.com"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific files found in PhishingKit
        $spec_file = "OutlookWeb_SignIn.php"
        $spec_file2 = "OutlookWeb_SignIn_validate.php"
        $spec_file3 = ".htaccess.txt"
        $spec_file4 = "robots.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}