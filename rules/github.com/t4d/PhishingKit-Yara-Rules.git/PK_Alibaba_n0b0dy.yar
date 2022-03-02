rule PK_Alibaba_n0b0dy : Alibaba
{
    meta:
        description = "Phishing Kit impersonating Alibaba"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-20"
        comment = "Phishing Kit - Alibaba - 'created by n0b0dy'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "data"
        $spec_file1 = "redirect.php"
        $spec_file2 = "index.html"
        $spec_file3 = "clear.png"
        $spec_file4 = "JSocket.swf"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}