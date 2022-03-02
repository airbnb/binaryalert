rule AveMaria
{
    meta:
        id = "7kTjKOPEjKKZRVTPh5LCPf"
        fingerprint = "6cf820532d1616bf7e0a16d2ccf0fb4c31df30e775fd9de1622ac840f55b2fee"
        version = "1.0"
        creation_date = "2020-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies AveMaria aka WarZone RAT."
        category = "MALWARE"
        malware = "WARZONERAT"
        malware_type = "RAT"
        mitre_att = "S0534"


    strings:
        $ = "AVE_MARIA" ascii wide
        $ = "Ave_Maria Stealer OpenSource" ascii wide
        $ = "Hey I'm Admin" ascii wide
        $ = "WM_DISP" ascii wide fullword
        $ = "WM_DSP" ascii wide fullword
        $ = "warzone160" ascii wide

    condition:
        3 of them
}