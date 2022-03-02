rule PK_Docusign_Unknow
{
    meta:
        description = "Docusign phishing kit created by Unknow"
        licence = ""
        author = "Guido Denzler"
        reference = ""
        date = "2020-02-25"
        comment = "Phishing Kit - Docusign - Unknow"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "docusign  letter2018 fud.html"
        $spec_file2 = "geoplugin.class.php"
        $spec_image1 = "DocuSign_logo_new.png"
        $spec_image2 = "docusign.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file
        and 2 of ($spec_file*)
        and any of ($spec_image*)
}
