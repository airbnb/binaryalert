rule PK_SwissPost_Redsys : SwissPost
{
    meta:
        description = "Phishing Kit impersonating Swiss Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-07-28"
        comment = "Phishing Kit - Swiss Post - using directory named 'Redsys_files'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Redsys_files"
        // specific file found in PhishingKit
        $spec_file = "Redsys.html"
        $spec_file2 = "Seleccione_gracias.php"
        $spec_file3 = "POST.svg"
        $spec_file4 = "deutsche.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        $spec_dir
}