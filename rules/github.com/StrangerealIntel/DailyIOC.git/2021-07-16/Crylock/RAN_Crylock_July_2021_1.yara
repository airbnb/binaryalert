rule RAN_Crylock_July_2021_1
{
    meta:
        description = "Detect CryLock ransomware (ex-Cryakl)"
        author = "Arkbird_SOLG"
        date = "2021-07-17"
        reference = "https://twitter.com/BushidoToken/status/1415958829318217730"
        hash1 = "a962501ea4cd363dd588c948ff8b0ab24aa4132ff58f4a7806af06efa3b791ef"
        hash2 = "1c2975dd464d014502a46ba6383943c7de4635e3664011653217dc424d53f8fe"
        hash3 = "e001f6a5b2d4d2659b010fb5825eb4383e8f415861a244329bc70cfcd18da507"
        tlp = "White"
        adversary = "RAAS"
    strings:
        $s1 = { 2f 63 20 22 70 69 6e 67 20 30 2e 30 2e 30 2e 30 26 64 65 6c 20 22 }
        $s2 = { 7b 45 4e 43 52 59 50 54 53 54 41 52 54 7d 7b }
        $s3 = { 7b 45 4e 43 52 59 50 54 45 4e 44 45 44 7d }
        $s4 = { 2f 2f 2f 45 4e 44 20 55 4e 45 4e 43 52 59 50 54 20 45 58 54 45 4e 41 54 49 4f 4e 53 5c 5c 5c 00 ff ff ff ff 17 00 00 00 2f 2f 2f 45 4e 44 20 43 4f 4d 4d 41 4e 44 53 20 4c 49 53 54 5c 5c 5c 00 ff ff ff ff 1d 00 00 00 2f 2f 2f 45 4e 44 20 50 52 4f 43 45 53 53 45 53 20 4b 49 4c 4c 20 4c 49 53 54 5c 5c 5c 00 00 00 ff ff ff ff 1c 00 00 00 2f 2f 2f 45 4e 44 20 53 45 52 56 49 43 45 53 20 53 54 4f 50 20 4c 49 53 54 5c 5c 5c 00 00 00 00 ff ff ff ff 1e 00 00 00 2f 2f 2f 45 4e 44 20 50 52 4f 43 45 53 53 45 53 20 57 48 49 54 45 20 4c 49 53 54 5c 5c 5c 00 00 ff ff ff ff 1e 00 00 00 2f 2f 2f 45 4e 44 20 55 4e 45 4e 43 52 59 50 54 20 46 49 4c 45 53 20 4c 49 53 54 5c 5c 5c 00 00 ff ff ff ff 20 00 00 00 2f 2f 2f 45 4e 44 20 55 4e 45 4e 43 52 59 50 54 20 46 4f 4c 44 45 52 53 20 4c 49 53 54 5c 5c 5c }
        $s5 = { 49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 }
        $s6 = { 3c 25 55 4e 44 45 43 52 59 50 54 5f 44 41 54 45 54 49 4d 45 25 3e }
        $s7 = { 25 00 73 00 20 00 28 00 25 00 73 00 2c 00 20 00 6c 00 69 00 6e 00 65 00 20 00 25 00 64 00 29 }
    condition:
        uint16(0) == 0x5a4d and filesize > 80KB and 6 of ($s*)
}
