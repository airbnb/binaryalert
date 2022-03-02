rule LaZagne
{
    meta:
        id = "3DeKZTrvc1lTK9vNaoj7LG"
        fingerprint = "81ef321369e94e5cb5bbf735ab7db8c6aafc1fc7564c76d53b3f0e0adb9e5c81"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LaZagne, credentials recovery project."
        category = "TOOL"
        tool = "LAZAGNE"
        mitre_att = "S0349"
        reference = "https://github.com/AlessandroZ/LaZagne"


    strings:
        $ = "[!] Specify a directory, not a file !" ascii wide
        $ = "lazagne.config" ascii wide
        $ = "lazagne.softwares" ascii wide
        $ = "blazagne.exe.manifest" ascii wide
        $ = "slaZagne" ascii wide fullword

    condition:
        any of them
}