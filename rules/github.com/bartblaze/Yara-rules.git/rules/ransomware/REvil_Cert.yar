import "pe"

rule REvil_Cert
{
    meta:
        id = "4KM2J6a6EP4OW0GGQEaBiI"
        fingerprint = "ab9783909f458776d59b75d74f885dfebcc543b690c5e46b738a28f25d651a9c"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies the digital certificate PB03 TRANSPORT LTD, used by REvil in the Kaseya supply chain attack."
        category = "MALWARE"
        malware = "REVIL"
        malware_type = "RANSOMWARE"
        mitre_att = "S0496"
        reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"


    condition:
        uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0")
}