rule Unk_BR_Banker
{
    meta:
        id = "5IYTPDXywF5zMWuDcnVYFz"
        fingerprint = "188bfe548c195449556fa093144b8bd7ed2eb6d506b1fd251ee6c131a34dc59b"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies an unknown Brazilian banking trojan."
        category = "MALWARE"
        malware_type = "BANKER"

    strings:
        $ = "<ALARME>" ascii wide
        $ = "<ALARME_G>" ascii wide
        $ = "<ALARME_R>" ascii wide
        $ = "<|LULUZDC|>" ascii wide
        $ = "<|LULUZLD|>" ascii wide
        $ = "<|LULUZLU|>" ascii wide
        $ = "<|LULUZPos|>" ascii wide
        $ = "<|LULUZRD|>" ascii wide
        $ = "<|LULUZRU|>" ascii wide
        $ = ">CRIAR_ALARME_AZUL<" ascii wide
        $ = ">ESCREVER_BOTAO_DIREITO<" ascii wide
        $ = ">REMOVER_ALARME_GRAY<" ascii wide
        $ = ">WIN_SETA_ACIMA<" ascii wide
        $ = ">WIN_SETA_BAIXO<" ascii wide
        $ = ">WIN_SETA_ESQUERDA<" ascii wide
        $ = "BOTAO_DIREITO" ascii wide

    condition:
        5 of them
}