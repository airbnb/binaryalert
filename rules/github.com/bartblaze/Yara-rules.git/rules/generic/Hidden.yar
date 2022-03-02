rule Hidden
{
    meta:
        id = "568PgDjhUwg620xlbE6vMk"
        fingerprint = "0fc71baad34741d864ec596e89fc873a01974d7ab6bea912d572c2bd2ae2e0da"
        version = "1.0"
        creation_date = "2021-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Hidden Windows driver, used by malware such as PurpleFox."
        category = "MALWARE"
        reference = "https://github.com/JKornev/hidden"


    strings:
        $ = "Hid_State" ascii wide
        $ = "Hid_StealthMode" ascii wide
        $ = "Hid_HideFsDirs" ascii wide
        $ = "Hid_HideFsFiles" ascii wide
        $ = "Hid_HideRegKeys" ascii wide
        $ = "Hid_HideRegValues" ascii wide
        $ = "Hid_IgnoredImages" ascii wide
        $ = "Hid_ProtectedImages" ascii wide
        $ = "Hid_HideImages" ascii wide

    condition:
        5 of them
}