import "hash"
import "pe"

rule DefenderControl
{
    meta:
        id = "5wrFItxbjAcaTcQm9RW9IR"
        fingerprint = "0afa43f0e67bfa81406319e6e4f3ab71e2fe63476a1b7cc06660a68369155cbb"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Defender Control, used by attackers to disable Windows Defender."
        category = "MALWARE"
        malware = "DEFENDERCONTROL"
        reference = "https://www.sordum.org/9480/defender-control-v1-8/"


    strings:
        $ = "www.sordum.org" ascii wide
        $ = "dControl.exe" ascii wide

    condition:
        all of them or ( for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="ff620e5c0a0bdcc11c3b416936bc661d"))
}