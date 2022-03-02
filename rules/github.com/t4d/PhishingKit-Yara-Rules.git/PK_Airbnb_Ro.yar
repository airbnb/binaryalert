rule PK_Airbnb_Ro : Airbnb
{
    meta:
        description = "Phishing Kit impersonating Airbnb"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-11-01"
        comment = "Phishing Kit - Airbnb - with several romanian sentences into source code"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "bnb_files"
        $spec_file1 = "loggen.htm"
        $spec_file2 = "room-16268.html"
        $spec_file3 = "action.php"
        $spec_file4 = "cdn_provider-955038e0686ec92cb7402ca76b957d11.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}