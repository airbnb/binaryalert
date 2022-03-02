rule BlackKingDom
{
    meta:
        id = "su4arxDGFAZfSHRVAv689"
        fingerprint = "504f4b0c26223ecc9af94b8e95cc80b777ba25ced07af89192e1777895460b2e"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies (decompiled) Black KingDom ransomware."
        category = "MALWARE"
        malware_type = "RANSOMWARE"

    strings:
        $ = "BLACLIST" ascii wide
        $ = "Black KingDom" ascii wide
        $ = "FUCKING_WINDOW" ascii wide
        $ = "PleasStopMe" ascii wide
        $ = "THE AMOUNT DOUBLED" ascii wide
        $ = "WOWBICH" ascii wide
        $ = "clear_logs_plz" ascii wide
        $ = "decrypt_file.TxT" ascii wide
        $ = "disable_Mou_And_Key" ascii wide
        $ = "encrypt_file" ascii wide
        $ = "for_fortnet" ascii wide
        $ = "start_encrypt" ascii wide
        $ = "where_my_key" ascii wide

    condition:
        3 of them
}