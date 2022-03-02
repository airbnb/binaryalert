rule Confucius_B
{
    meta:
        id = "3AaavteplEPTLc29oIVtzm"
        fingerprint = "f7a7224bfdbb79208776c856eb05a59ed75112376d0d3b28776305efc94c0414"
        version = "1.0"
        creation_date = "2020-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Confucius malware."
        category = "MALWARE"
        malware = "CONFUCIUS"
        malware_type = "BACKDOOR"
        reference = "https://unit42.paloaltonetworks.com/unit42-confucius-says-malware-families-get-further-by-abusing-legitimate-websites/"


    strings:
        $ = "----BONE-79A8DE0E314C50503FF2378aEB126363-" ascii wide
        $ = "----MUETA-%.08x%.04x%.04x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x-" ascii wide
        $ = "C:\\Users\\DMITRY-PC\\Documents\\JKE-Agent-Win32\\JKE_Agent_DataCollectorPlugin\\output\\Debug\\JKE_Agent_DumbTestPlugin.dll" ascii wide

    condition:
        any of them
}