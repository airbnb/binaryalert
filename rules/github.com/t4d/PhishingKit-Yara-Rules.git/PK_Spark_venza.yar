rule PK_Spark_venza : Spark
{
    meta:
        description = "Phishing Kit impersonating Spark"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-22"
        comment = "Phishing Kit - Spark - 'CrEaTeD bY VeNzA'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_file1 = "email.php"
        $spec_file2 = "next.php"
        $spec_file3 = "myspark-identity-bg.jpg"
        $spec_file4 = "clientlib-sparkv2.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}