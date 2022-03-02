import "pe"

rule Gmer
{
    meta:
        id = "8rI4CpbchoNUbZrro3sSW"
        fingerprint = "c8f734a69a66e320dba787e7a0d522c5db3566cd53b8ffcf855317996b8ec063"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Gmer, sometimes used by attackers to disable security software."
        category = "MALWARE"
        reference = "http://www.gmer.net/"


    strings:
        $ = "GMER %s - %s" ascii wide
        $ = "IDI_GMER" ascii wide fullword
        $ = "E:\\projects\\cpp\\gmer\\Release\\gmer.pdb" ascii wide

    condition:
        any of them
}