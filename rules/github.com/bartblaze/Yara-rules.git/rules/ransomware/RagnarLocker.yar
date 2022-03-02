rule RagnarLocker
{
    meta:
        id = "5066KiqBNrcicJGfWPfDx5"
        fingerprint = "fd403ea38a9c6c269ff7b72dea1525010f44253a41e72bf3fce55fa4623245a3"
        version = "1.0"
        creation_date = "2020-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RagnarLocker ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "RAGNAR LOCKER"
        malware_type = "RANSOMWARE"
        mitre_att = "S0481"

    strings:
        $ = "RAGNRPW" ascii wide
        $ = "---END KEY R_R---" ascii wide
        $ = "---BEGIN KEY R_R---" ascii wide

    condition:
        any of them
}