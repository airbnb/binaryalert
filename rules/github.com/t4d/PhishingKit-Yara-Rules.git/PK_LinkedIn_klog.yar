rule PK_LinkedIn_klog : LinkedIn
{
    meta:
        description = "Phishing Kit impersonating LinkedIn"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-18"
        comment = "Phishing Kit - LinkedIn - 'KLOG'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "request_data"
        $spec_file1 = "process.php"
        $spec_file2 = "checkpoint-frontendstylesheetsloginorganicdesktop_en_US.css"
        $spec_file3 = "myolo_frame_library.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
