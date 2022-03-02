rule MalScript_Tricks
{
    meta:
        id = "3xg5wneq3ZntsMg61ltshS"
        fingerprint = "6c78cbc1250afb36970d87d8ee2fe8409f57c9d34251d6e3908454e6643f92e3"
        version = "1.0"
        creation_date = "2020-12-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies tricks often seen in malicious scripts such as moving the window off-screen or resizing it to zero."
        category = "MALWARE"

    strings:
        $s1 = "window.moveTo -" ascii wide nocase
        $s2 = "window.resizeTo 0" ascii wide nocase
        $x1 = "window.moveTo(-" ascii wide nocase
        $x2 = "window.resizeTo(" ascii wide nocase

    condition:
        ( all of ($s*) or all of ($x*)) and filesize <50KB
}