rule Zeppelin
{
    meta:
        id = "RIttcGgKqwaotJyTgah7j"
        fingerprint = "a4da7defafa7f510df1c771e3d67bf5d99f3684a44f56d2b0e6f40f0a7fea84f"
        version = "1.0"
        creation_date = "2019-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Zeppelin ransomware and variants (Buran, Vega etc.)"
        category = "MALWARE"
        malware = "ZEPPELIN"
        malware_type = "RANSOMWARE"

    strings:
        $s1 = "TUnlockAndEncryptU" ascii wide
        $s2 = "TDrivesAndShares" ascii wide
        $s3 = "TExcludeFoldersU" ascii wide
        $s4 = "TExcludeFiles" ascii wide
        $s5 = "TTaskKillerU" ascii wide
        $s6 = "TPresenceU" ascii wide
        $s7 = "TSearcherU" ascii wide
        $s8 = "TReadme" ascii wide
        $s9 = "TKeyObj" ascii wide
        $x = "TZeppelinU" ascii wide

    condition:
        2 of ($s*) or $x
}