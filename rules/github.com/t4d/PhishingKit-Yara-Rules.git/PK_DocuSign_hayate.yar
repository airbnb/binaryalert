rule PK_DocuSign_hayate : DocuSign
{
    meta:
        description = "Phishing Kit impersonating DocuSign"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-04"
        comment = "Phishing Kit - DocuSign - 'BY HAYATE'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "other"
        $spec_file1 = "sc.php"
        $spec_file2 = "Login.php"
        $spec_file3 = "blockerz.php"
        $spec_file4 = "powered_by_docusign_gray.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}