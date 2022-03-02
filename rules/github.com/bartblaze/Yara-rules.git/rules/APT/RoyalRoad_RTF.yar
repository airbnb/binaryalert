rule RoyalRoad_RTF
{
    meta:
        id = "p1XW7z3B1sdN89zXF7Nel"
        fingerprint = "52be45a991322fa96f4e806cf6fa7a77886f63799c1f67723484bc3796363a4e"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RoyalRoad RTF, used by multiple Chinese APT groups."
        category = "MALWARE"
        malware = "ROYALROAD"        
        malware_type = "EXPLOITKIT"
        reference = "https://nao-sec.org/2020/01/an-overhead-view-of-the-royal-road.html"


    strings:
        $rtf = "{\\rt"
        $RR1 = "5C746D705C382E74" ascii wide nocase
        $RR2 = "5C417070446174615C4C6F63616C5C54656D705C382E74" ascii wide nocase

    condition:
        $rtf at 0 and any of ($RR*)
}