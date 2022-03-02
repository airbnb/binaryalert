import "pe"

rule Gmer_Driver
{
    meta:
        id = "47o6RMYvn1Hb14eggdrcHy"
        fingerprint = "7cc773597ea063add205ee1bce0ccce287d6f548ecb317923e83078a7018ed77"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Gmer's driver, sometimes used by attackers to disable security software."
        category = "MALWARE"
        reference = "http://www.gmer.net/"


    strings:
        $ = "e:\\projects\\cpp\\gmer\\driver64\\objfre_wlh_amd64\\amd64\\gmer64.pdb" ascii wide
        $ = "GMER Driver http://www.gmer.net" ascii wide

    condition:
        any of them or pe.version_info["OriginalFilename"] contains "gmer64.sys" or pe.version_info["InternalName"] contains "gmer64.sys"
}