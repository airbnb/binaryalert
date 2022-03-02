rule PK_Ameli_Don : Ameli
{
    meta:
        description = "Phishing Kit impersonating Ameli.fr"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-02"
        comment = "Phishing Kit - Ameli - 'From: mrazert'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Compte ameli - mon espace personnel_files"
        $spec_file1 = "biblicnam-standalone.min.js"
        $spec_file2 = "infos.php"
        $spec_file3 = "Compte ameli - mon espace personnel.html"
        $spec_file4 = "AideSaisie.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}