rule Adfind
{
    meta:
        id = "369wFVCBXsVYywgZZJhUjW"
        fingerprint = "296292e4e665d7eb2d36b2ad655d451cdf89bc27d2705bb8cb97fa34afcd16cb"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adfind, a Command line Active Directory query tool."
        category = "HACKTOOL"
        tool = "ADFIND"
        mitre_att = "S0552"
        reference = "http://www.joeware.net/freetools/tools/adfind/"


    strings:
        $ = "E:\\DEV\\cpp\\vs\\AdFind\\AdFind\\AdFind.cpp" ascii wide
        $ = "adfind.cf" ascii wide
        $ = "adfind -" ascii wide
        $ = "adfind /" ascii wide
        $ = "you have encountered a STAT binary blob that" ascii wide

    condition:
        any of them
}