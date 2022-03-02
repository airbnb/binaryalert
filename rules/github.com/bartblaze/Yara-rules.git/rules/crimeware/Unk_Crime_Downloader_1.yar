import "pe"

rule Unk_Crime_Downloader_1
{
    meta:
        id = "5T0oYPMEQOSKnlIWNqI5y"
        fingerprint = "826ce149c9b9f2aa04176213db1a8e8c8a57f0c2bcaeceb532a8282b80c31f7b"
        version = "1.0"
        creation_date = "2020-10-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Unknown downloader DLL, likely used by Emotet and/or TrickBot."
        category = "MALWARE"
        malware = "EMOTET"
        malware_type = "DOWNLOADER"
        mitre_att = "S0367"
        hash = "3d2ca7dc3d7c0aa120ed70632f9f0a15"

    strings:
        $ = "LDR.dll" ascii wide fullword
        $ = "URLDownloadToFileA" ascii wide

    condition:
        all of them or pe.imphash()=="4f8a708f1b809b780e4243486a40a465"
}