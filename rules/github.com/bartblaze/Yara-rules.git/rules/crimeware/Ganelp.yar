rule Ganelp
{
    meta:
        id = "5F6Z2reWdIRSLeXi6gf4RQ"
        fingerprint = "500d37e54fb6ba61cdfa9345db18e452d13288a8a42f24e1a55f3d24fbcf5bd0"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Ganelp, a worm that also spreads via USB."
        category = "MALWARE"
        malware = "GANELP"
        malware_type = "WORM"
        

    strings:
        $ = "regardez cette photo :D %s" ascii wide
        $ = "to fotografiu :D %s" ascii wide
        $ = "vejte se na mou fotku :D %s" ascii wide
        $ = "bekijk deze foto :D %s" ascii wide
        $ = "spojrzec na to zdjecie :D %s" ascii wide
        $ = "bu resmi bakmak :D %s" ascii wide
        $ = "dette bildet :D %s" ascii wide
        $ = "seen this?? :D %s" ascii wide
        $ = "guardare quest'immagine :D %s" ascii wide
        $ = "denna bild :D %s" ascii wide
        $ = "olhar para esta foto :D %s" ascii wide
        $ = "uita-te la aceasta fotografie :D %s" ascii wide
        $ = "pogledaj to slike :D %s" ascii wide
        $ = "poglej to fotografijo :D %s" ascii wide
        $ = "dette billede :D %s" ascii wide

    condition:
        3 of them
}