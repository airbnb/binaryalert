rule Darkside
{
    meta:
        id = "5qjcs58k9iHd3EU3xv66sV"
        fingerprint = "57bc5c7353c8c518e057456b2317e1dbf59ee17ce69cd336f1bacaf627e9efd5"
        version = "1.0"
        creation_date = "2021-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Darkside ransomware."
        category = "MALWARE"
        malware = "DARKSIDE"
        malware_type = "RANSOMWARE"

    strings:
        $ = "darkside_readme.txt" ascii wide
        $ = "[ Welcome to DarkSide ]" ascii wide
        $ = { 66 c7 04 47 2a 00 c7 44 47 02 72 00 65 00 c7 44 47 06 63 00 79 00 c7 44 47 0a 63 00 6c 00 c7 44 47 0e 65 00 2a 00 66 c7 44 47 12 00 00 }
        $ = { c7 00 2a 00 72 00 c7 40 04 65 00 63 00 c7 40 08 79 00 63 00 c7 40 0c 6c 00 65 00 c7 40 10 2a 00 00 00 }

    condition:
        any of them
}