rule Parallax
{
    meta:
        id = "7AHV77y7ZoCjGyFbljjWV6"
        fingerprint = "3ae9c820e411829619984c5e5311e8940248a771cfde3f22d2789ccb3c099be8"
        version = "1.0"
        creation_date = "2020-09-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Parallax RAT."
        category = "MALWARE"
        malware = "PARALLAX"
        malware_type = "RAT"

    strings:
        $ = ".DeleteFile(Wscript.ScriptFullName)" ascii wide
        $ = ".DeleteFolder" ascii wide fullword
        $ = ".FileExists" ascii wide fullword
        $ = "= CreateObject" ascii wide fullword
        $ = "Clipboard Start" ascii wide fullword
        $ = "UN.vbs" ascii wide fullword
        $ = "[Alt +" ascii wide fullword
        $ = "[Clipboard End]" ascii wide fullword
        $ = "[Ctrl +" ascii wide fullword

    condition:
        3 of them
}