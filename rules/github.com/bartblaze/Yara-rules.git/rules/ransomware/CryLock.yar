rule CryLock
{
    meta:
        id = "2l4H1zr9CK35G8zGAmRQAk"
        fingerprint = "f3084da9bc523ee78f0a85e439326c2f4a348330bf228192ca07c543f5fb04ed"
        version = "1.0"
        creation_date = "2020-09-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies CryLock aka Cryakl ransomware."
        category = "MALWARE"
        malware = "CRYLOCK"
        malware_type = "RANSOMWARE"

    strings:
        $ = "///END ENCRYPT ONLY EXTENATIONS" ascii wide
        $ = "///END UNENCRYPT EXTENATIONS" ascii wide
        $ = "///END COMMANDS LIST" ascii wide
        $ = "///END PROCESSES KILL LIST" ascii wide
        $ = "///END SERVICES STOP LIST" ascii wide
        $ = "///END PROCESSES WHITE LIST" ascii wide
        $ = "///END UNENCRYPT FILES LIST" ascii wide
        $ = "///END UNENCRYPT FOLDERS LIST" ascii wide
        $ = "{ENCRYPTENDED}" ascii wide
        $ = "{ENCRYPTSTART}" ascii wide

    condition:
        2 of them
}