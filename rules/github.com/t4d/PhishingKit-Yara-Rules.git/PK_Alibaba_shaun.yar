rule PK_Alibaba_shaun : Alibaba
{
    meta:
        description = "Phishing Kit impersonating Alibaba"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-10"
        comment = "Phishing Kit - Alibaba - 'By Shaun'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "li.php"
        $spec_file2 = "login.php"
        $spec_file3 = "message.html"
        $spec_file4 = "ali link.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}