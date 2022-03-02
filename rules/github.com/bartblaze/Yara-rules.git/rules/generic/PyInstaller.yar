import "hash"
import "pe"

rule PyInstaller
{
    meta:
        id = "6Pyq57uDDAEHbltmbp7xRT"
        fingerprint = "ae849936b19be3eb491d658026b252c2f72dcb3c07c6bddecb7f72ad74903eee"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable converted using PyInstaller."
        category = "MALWARE"

    strings:
        $ = "pyi-windows-manifest-filename" ascii wide
        $ = "pyi-runtime-tmpdir" ascii wide
        $ = "PyInstaller: " ascii wide

    condition:
        uint16(0)==0x5a4d and any of them or ( for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="20d36c0a435caad0ae75d3e5f474650c"))
}