rule Maze
{
    meta:
        id = "4sTbmIEE40nSKc9rOEz4po"
        fingerprint = "305df5e5f0a4d5660dff22073881e65ff25528895abf26308ecd06dd70a97ec2"
        version = "1.0"
        creation_date = "2019-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Maze ransomware in memory or unpacked."
        category = "MALWARE"
        malware = "MAZE"
        malware_type = "RANSOMWARE"
        mitre_att = "S0449"

    strings:
        $ = "Enc: %s" ascii wide
        $ = "Encrypting whole system" ascii wide
        $ = "Encrypting specified folder in --path parameter..." ascii wide
        $ = "!Finished in %d ms!" ascii wide
        $ = "--logging" ascii wide
        $ = "--nomutex" ascii wide
        $ = "--noshares" ascii wide
        $ = "--path" ascii wide
        $ = "Logging enabled | Maze" ascii wide
        $ = "NO SHARES | " ascii wide
        $ = "NO MUTEX | " ascii wide
        $ = "Encrypting:" ascii wide
        $ = "You need to buy decryptor in order to restore the files." ascii wide
        $ = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" ascii wide
        $ = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" ascii wide
        $ = "DECRYPT-FILES.txt" ascii wide fullword

    condition:
        5 of them
}