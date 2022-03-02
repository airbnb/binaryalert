rule CrunchyRoll
{
    meta:
        id = "6MWD1MRYK1S03fFM5QvlHP"
        fingerprint = "2e0d0a32f42c7c8b800c373a229af29185a2a8c59eb7067de4acc0bcda232f23"
        version = "1.0"
        creation_date = "2019-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies malware used in CrunchyRoll website hack."
        category = "MALWARE"
        reference = "https://bartblaze.blogspot.com/2017/11/crunchyroll-hack-delivers-malware.html"


    strings:
        $ = "C:\\Users\\Ben\\Desktop\\taiga-develop\\bin\\Debug\\Taiga.pdb" ascii wide
        $ = "c:\\users\\ben\\source\\repos\\svchost\\Release\\svchost.pdb" ascii wide

    condition:
        any of them
}