rule PK_Docanvas_tangular : DoCANVAS
{
    meta:
        description = "Phishing Kit impersonating NTT DoCANVAS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-07-08"
        comment = "Phishing Kit - DoCanvas - presence of 'T_a_n_G_u_l_AR' directory name in phishing kit"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "T_a_n_G_u_l_AR"
        $spec_file1 = "grabber.php"
        $spec_file2 = "anti8.php"
        $spec_file3 = "dashboard.css"
        $spec_file4 = "MyBabyTwo.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
