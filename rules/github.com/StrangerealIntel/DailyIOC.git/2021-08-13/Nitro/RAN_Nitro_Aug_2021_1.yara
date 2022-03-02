rule RAN_Nitro_Aug_2021_1
{
    meta:
        description = "Detect Nitro ransomware"
        author = "Arkbird_SOLG"
        date = "2021-08-12"
        reference = "https://bazaar.abuse.ch/browse/tag/NitroRansomware/"
        hash1 = "1194aebc9a0016084f6966b07a171e4c62ce1b21580d177a876873641692ee13"
        hash2 = "6546f0638160cb590b4ead2401fb55d48e10b2ee1808ff0354fff52c9e2f62bf"
        hash3 = "89dbea1e4b387325f21c784dc72fcf52599f69e1ded27d1b830ff57ae4831559"
        hash4 = "d8e9561612c6e06160d79abde41c7b66e4921a1c041ad5c2658d43050b4fd2d0"
        hash5 = "dbed3399932fabe6f7f863403279ac9a6b075aa307dd445df2c7060157d3063b"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = { 1f 1a 28 ?? 00 00 0a [0-2] 72 ?? 14 00 70 28 15 00 00 0a 80 32 00 00 04 28 ?? 00 00 06 7e 32 00 00 04 6f ?? 00 00 0a [0-1] 7e 2f 00 00 04 16 7e 32 00 00 04 7e 30 00 00 04 7e 31 00 00 04 60 28 ?? 00 00 06 26 2a }
        $s2 = { 02 [0-5] 72 df 00 00 70 28 1b 00 00 }
        $s3 = { 1f 1a 28 ?? 00 00 0a 0a 1f 1c 28 ?? 00 00 0a 0b 7e 21 00 00 04 06 72 ?? 0c 00 70 28 15 00 00 0a 6f 16 00 00 0a [2] ?? 00 }
        $s4 = { 7e 4e 00 00 0a 0a [0-1] 72 [2] 00 70 73 ?? 00 00 06 0b [0-1] 07 72 [2] 00 70 6f ?? 00 00 06 [1-3] 8d 7f 00 00 01 25 16 1f 0a 9d 6f ?? 00 00 0a 1c 9a 0a [0-1] de ?? 07 2c ?? 07 6f 42 00 00 0a } 
        $s5 = { 7e 4e 00 00 0a 0a [0-1] 73 ?? 00 00 0a 0b [0-1] 07 72 ?? 14 00 70 6f ?? 00 00 0a [0-2] 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a [0-2] 6f ?? 00 00 0a 0a }
    condition:
        uint16(0) == 0x5A4D and filesize > 25KB and all of ($s*)
}
