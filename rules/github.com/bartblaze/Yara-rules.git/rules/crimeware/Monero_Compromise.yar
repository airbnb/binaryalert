rule Monero_Compromise
{
    meta:
        id = "2oIDqilozjDoCoilh0uEV2"
        fingerprint = "749f8aa9e70217387a3491e3e050d37e85fee65e50ae476e58a1dc77198fc017"
        version = "1.0"
        creation_date = "2019-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies compromised Monero binaries."
        category = "MALWARE"
        reference = "https://bartblaze.blogspot.com/2019/11/monero-project-compromised.html"


    strings:
        $ = "ZN10cryptonote13simple_wallet9send_seedERKN4epee15wipeable_stringE" ascii wide
        $ = "ZN10cryptonote13simple_wallet10send_to_ccENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES6_i" ascii wide
        $ = "node.xmrsupport.co" ascii wide
        $ = "node.hashmonero.com" ascii wide

    condition:
        any of them
}