rule PK_Otenet_notepad : otenet
{
    meta:
        description = "Phishing Kit impersonating Cosmote Webmail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-20"
        comment = "Phishing Kit - Otenet - 'file_put_contents(notepad.txt'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "tools.otenet.gr"
        $spec_file2 = "notepad.txt"
        $spec_file3 = "send.php"
        $spec_file4 = "terms.pdf"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and 
        // check for files
        all of ($spec_file*)
}
