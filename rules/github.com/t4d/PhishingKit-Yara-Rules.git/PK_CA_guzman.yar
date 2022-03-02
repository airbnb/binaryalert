rule PK_CA_guzman : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://stalkphish.com/2020/12/14/how-phishing-kits-use-telegram/"
        date = "2021-04-02"
        comment = "Phishing Kit - Credit Agricole - 'Author: Guzman' - based on z0n51"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "z0n51"
        $spec_dir2 = "phpmailer"
        $spec_file1 = "_media-queries.scss"
        $spec_file2 = "resulttt987.txt"
        $spec_file3 = "get_oauth_token.php"
        $spec_file4 = "cc_details.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
