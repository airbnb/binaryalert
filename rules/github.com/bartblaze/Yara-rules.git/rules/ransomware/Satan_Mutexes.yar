rule Satan_Mutexes
{
    meta:
        id = "4jKp8prwufSCRdyuJPHFX3"
        fingerprint = "4c325bd0f020e626a484338a3f88cbcf6c14bfa10201e52c2fde8c7c331988fb"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Satan ransomware (and its variants) by mutex."
        category = "MALWARE"
        malware = "SATAN"
        malware_type = "RANSOMWARE"
        reference = "https://bartblaze.blogspot.com/2020/01/satan-ransomware-rebrands-as-5ss5c.html"


    strings:
        $ = "SATANAPP" ascii wide
        $ = "SATAN_SCAN_APP" ascii wide
        $ = "STA__APP" ascii wide
        $ = "DBGERAPP" ascii wide
        $ = "DBG_CPP" ascii wide
        $ = "run_STT" ascii wide
        $ = "SSS_Scan" ascii wide
        $ = "SSSS_Scan" ascii wide
        $ = "5ss5c_CRYPT" ascii wide

    condition:
        any of them
}