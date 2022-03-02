rule BazarBackdoor
{
    meta:
        id = "457CJ7xNoBZJ2ChWuy0zgq"
        fingerprint = "b16f9a0651d90b68dced444c7921fd594b36f7672c29daf9fcbdb050f7655519"
        version = "1.0"
        creation_date = "2020-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Bazar backdoor."
        category = "MALWARE"
        malware = "BAZAR BACKDOOR"
        malware_type = "BACKDOOR"
        mitre_att = "S0534"
        reference = "https://www.bleepingcomputer.com/news/security/bazarbackdoor-trickbot-gang-s-new-stealthy-network-hacking-malware/"


    strings:
        $ = { c7 44 ?? ?? 6d 73 67 3d c7 44 ?? ?? 6e 6f 20 66 c7 44 ?? ?? 69 6c 65 00  }
        $ = { c7 44 ?? ?? 43 4e 20 3d 4? 8b f1 4? 89 b? ?? ?? ?? ?? 33 d2 4? 89 b? ?? ?? ?? ?? 4? 8d ?? ?4 60 4? 89 b? ?? ?? ?? ?? 4? 8d 7f 10 c7 44 ?? ?? 20 6c 6f 63 4? 8b c7 c7 44 ?? ?? 61 6c 68 6f 4? 8b df 66 c7 44 ?? ?? 73 74  }

    condition:
        any of them
}