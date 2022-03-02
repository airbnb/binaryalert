import "pe"

rule INDICATOR_KB_CERT_56203db039adbd6094b6a142c5e50587 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e438c77483ecab0ff55cc31f2fd2f835958fad80"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bccabdacabbdcda" and
            pe.signatures[i].serial == "56:20:3d:b0:39:ad:bd:60:94:b6:a1:42:c5:e5:05:87"
        )
}

rule INDICATOR_KB_CERT_b5f34b7c326c73c392b515eb4c2ec80e {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "9d35805d6311fd2fe6c49427f55f0b4e2836bbc5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cdaadbffbaedaabbdedfdbfebf" and
            pe.signatures[i].serial == "b5:f3:4b:7c:32:6c:73:c3:92:b5:15:eb:4c:2e:c8:0e"
        )
}

rule INDICATOR_KB_CERT_0a1dc99e4d5264c45a5090f93242a30a {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "17680b1ebaa74f94272957da11e914a3a545f16f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "K & D KOMPANI d.o.o." and
            pe.signatures[i].serial == "0a:1d:c9:9e:4d:52:64:c4:5a:50:90:f9:32:42:a3:0a"
        )
}

rule INDICATOR_KB_CERT_0d53690631dd186c56be9026eb931ae2 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c5d1e46a40a8200587d067814adf0bbfa09780f5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STA-R TOV" and
            pe.signatures[i].serial == "0d:53:69:06:31:dd:18:6c:56:be:90:26:eb:93:1a:e2"
        )
}

rule INDICATOR_KB_CERT_fd8c468cc1b45c9cfb41cbd8c835cc9e {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "08fc56a14dcdc9e67b9a890b65064b8279176057"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pivo ZLoun s.r.o." and
            pe.signatures[i].serial == "fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e"
        )
}

rule INDICATOR_KB_CERT_32fbf8cfa43dca3f85efabe96dfefa49 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "498d63bf095195828780dba7b985b71ab08e164f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Foxstyle LLC" and
            pe.signatures[i].serial == "32:fb:f8:cf:a4:3d:ca:3f:85:ef:ab:e9:6d:fe:fa:49"
        )
}

rule INDICATOR_KB_CERT_7e0ccda0ef37acef6c2ebe4538627e5c {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "a758d6799e218dd66261dc5e2e21791cbcccd6cb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Orangetree B.V." and
            pe.signatures[i].serial == "7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c"
        )
}

rule INDICATOR_KB_CERT_0095e5793f2abe0b4ec9be54fd24f76ae5 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "6acdfee2a1ab425b7927d0ffe6afc38c794f1240"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kommservice LLC" and
            pe.signatures[i].serial == "00:95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5"
        )
}

rule INDICATOR_KB_CERT_00c167f04b338b1e8747b92c2197403c43 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "7af7df92fa78df96d83b3c0fd9bee884740572f9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and
            pe.signatures[i].serial == "00:c1:67:f0:4b:33:8b:1e:87:47:b9:2c:21:97:40:3c:43"
        )
}

rule INDICATOR_KB_CERT_00fc7065abf8303fb472b8af85918f5c24 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "b61a6607154d27d64de35e7529cb853dcb47f51f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DIG IN VISION SP Z O O" and
            pe.signatures[i].serial == "00:fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24"
        )
}

rule INDICATOR_KB_CERT_00b61b8e71514059adc604da05c283e514 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "67ee69f380ca62b28cecfbef406970ddd26cd9be"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APP DIVISION ApS" and
            pe.signatures[i].serial == "00:b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14"
        )
}

rule INDICATOR_KB_CERT_51cd5393514f7ace2b407c3dbfb09d8d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "07a9fd6af84983dbf083c15983097ac9ce761864"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APPI CZ a.s" and
            pe.signatures[i].serial == "51:cd:53:93:51:4f:7a:ce:2b:40:7c:3d:bf:b0:9d:8d"
        )
}

rule INDICATOR_KB_CERT_030012f134e64347669f3256c7d050c5 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "959caa354b28892608ab1bb9519424c30bebc155"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Futumarket LLC" and
            pe.signatures[i].serial == "03:00:12:f1:34:e6:43:47:66:9f:32:56:c7:d0:50:c5"
        )
}

rule INDICATOR_KB_CERT_00b7f19b13de9bee8a52ff365ced6f67fa {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "61708a3a2bae5343ff764de782d7f344151f2b74"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALEXIS SECURITY GROUP, LLC" and
            pe.signatures[i].serial == "00:b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa"
        )
}

rule INDICATOR_KB_CERT_4c8def294478b7d59ee95c61fae3d965 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = ""
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DREAM SECURITY USA INC" and
            pe.signatures[i].serial == "4c:8d:ef:29:44:78:b7:d5:9e:e9:5c:61:fa:e3:d9:65"
        )
}

rule INDICATOR_KB_CERT_0a23b660e7322e54d7bd0e5acc890966 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c1e0c6dc2bc8ea07acb0f8bdb09e6a97ae91e57c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ARTBUD RADOM SP Z O O" and
            pe.signatures[i].serial == "0a:23:b6:60:e7:32:2e:54:d7:bd:0e:5a:cc:89:09:66"
        )
}

rule INDICATOR_KB_CERT_04332c16724ffeda5868d22af56aea43 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "cba350fe1847a206580657758ad6813a9977c40e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bespoke Software Solutions Limited" and
            pe.signatures[i].serial == "04:33:2c:16:72:4f:fe:da:58:68:d2:2a:f5:6a:ea:43"
        )
}

rule INDICATOR_KB_CERT_085b70224253486624fc36fa658a1e32 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "36834eaf0061cc4b89a13e019eccc6e598657922"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Best Fud, OOO" and
            pe.signatures[i].serial == "08:5b:70:22:42:53:48:66:24:fc:36:fa:65:8a:1e:32"
        )
}

rule INDICATOR_KB_CERT_0086e5a9b9e89e5075c475006d0ca03832 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "76f6c507e0bcf7c6b881f117936f5b864a3bd3f8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BlueMarble GmbH" and
            pe.signatures[i].serial == "00:86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32"
        )
}

rule INDICATOR_KB_CERT_039668034826df47e6207ec9daed57c3 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "f98bdfa941ebfa2fe773524e0f9bbe9072873c2f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CHOO FSP, LLC" and
            pe.signatures[i].serial == "03:96:68:03:48:26:df:47:e6:20:7e:c9:da:ed:57:c3"
        )
}

rule INDICATOR_KB_CERT_736dcfd309ea4c3bea23287473ffe071 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "8bfc13bf01e98e5b38f8f648f0f843b63af03f55"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ESTELLA, OOO" and
            pe.signatures[i].serial == "73:6d:cf:d3:09:ea:4c:3b:ea:23:28:74:73:ff:e0:71"
        )
}

rule INDICATOR_KB_CERT_09c89de6f64a7fdf657e69353c5fdd44 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "7ad763dfdaabc1c5a8d1be582ec17d4cdcbd1aeb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EXON RENTAL SP Z O O" and
            pe.signatures[i].serial == "09:c8:9d:e6:f6:4a:7f:df:65:7e:69:35:3c:5f:dd:44"
        )
}

rule INDICATOR_KB_CERT_03b630f9645531f8868dae8ac0f8cfe6 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "ab027825daf46c5e686e4d9bc9c55a5d8c5e957d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Geksan LLC" and
            pe.signatures[i].serial == "03:b6:30:f9:64:55:31:f8:86:8d:ae:8a:c0:f8:cf:e6"
        )
}

rule INDICATOR_KB_CERT_020bc03538fbdc792f39d99a24a81b97 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "0ab2629e4e721a65ad35758d1455c1202aa643d3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GLOBAL PARK HORIZON SP Z O O" and
            pe.signatures[i].serial == "02:0b:c0:35:38:fb:dc:79:2f:39:d9:9a:24:a8:1b:97"
        )
}

rule INDICATOR_KB_CERT_4e8d4fc7d9f38aca1169fbf8ef2aaf50 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "7239764d40118fc1574a0af77a34e369971ddf6d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "INFINITE PROGRAMMING LIMITED" and
            pe.signatures[i].serial == "4e:8d:4f:c7:d9:f3:8a:ca:11:69:fb:f8:ef:2a:af:50"
        )
}

rule INDICATOR_KB_CERT_09830675eb483e265c3153f0a77c3de9 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "1bb5503a2e1043616b915c4fce156c34304505d6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "James LTH d.o.o." and
            pe.signatures[i].serial == "09:83:06:75:eb:48:3e:26:5c:31:53:f0:a7:7c:3d:e9"
        )
}

rule INDICATOR_KB_CERT_351fe2efdc0ac56a0c822cf8 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "4230bca4b7e4744058a7bb6e355346ff0bbeb26f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Logika OOO" and
            pe.signatures[i].serial == "35:1f:e2:ef:dc:0a:c5:6a:0c:82:2c:f8"
        )
}

rule INDICATOR_KB_CERT_07bb6a9d1c642c5973c16d5353b17ca4 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "9de562e98a5928866ffc581b794edfbc249a2a07"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MADAS d.o.o." and
            pe.signatures[i].serial == "07:bb:6a:9d:1c:64:2c:59:73:c1:6d:53:53:b1:7c:a4"
        )
}

rule INDICATOR_KB_CERT_044e05bb1a01a1cbb50cfb6cd24e5d6b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "149b7bbe88d4754f2900c88516ce97be605553ff"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MUSTER PLUS SP Z O O" and
            pe.signatures[i].serial == "04:4e:05:bb:1a:01:a1:cb:b5:0c:fb:6c:d2:4e:5d:6b"
        )
}

rule INDICATOR_KB_CERT_0c14b611a44a1bae0e8c7581651845b6 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c3288c7fbb01214c8f2dc3172c3f5c48f300cb8b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NEEDCODE SP Z O O" and
            pe.signatures[i].serial == "0c:14:b6:11:a4:4a:1b:ae:0e:8c:75:81:65:18:45:b6"
        )
}

rule INDICATOR_KB_CERT_0b1926a5e8ae50a0efa504f005f93869 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "2052ed19dcb0e3dfff71d217be27fc5a11c0f0d4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nordkod LLC" and
            pe.signatures[i].serial == "0b:19:26:a5:e8:ae:50:a0:ef:a5:04:f0:05:f9:38:69"
        )
}

rule INDICATOR_KB_CERT_0bab6a2aa84b495d9e554a4c42c0126d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "230614366ddac05c9120a852058c24fa89972535"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NOSOV SP Z O O" and
            pe.signatures[i].serial == "0b:ab:6a:2a:a8:4b:49:5d:9e:55:4a:4c:42:c0:12:6d"
        )
}

rule INDICATOR_KB_CERT_066226cf6a4d8ae1100961a0c5404ff9 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "8c762918a58ebccb1713720c405088743c0d6d20"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO MEP" and
            pe.signatures[i].serial == "06:62:26:cf:6a:4d:8a:e1:10:09:61:a0:c5:40:4f:f9"
        )
}

rule INDICATOR_KB_CERT_0e96837dbe5f4548547203919b96ac27 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d6c6a0a4a57af645c9cad90b57c696ad9ad9fcf9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PLAN CORP PTY LTD" and
            pe.signatures[i].serial == "0e:96:83:7d:be:5f:45:48:54:72:03:91:9b:96:ac:27"
        )
}

rule INDICATOR_KB_CERT_5b320a2f46c99c1ba1357bee {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "5ae8bd51ffa8e82f8f3d8297c4f9caf5e30f425a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REGION TOURISM LLC" and
            pe.signatures[i].serial == "5b:32:0a:2f:46:c9:9c:1b:a1:35:7b:ee"
        )
}

rule INDICATOR_KB_CERT_02c5351936abe405ac760228a40387e8 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "1174c2affb0a364c1b7a231168cfdda5989c04c5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RESURS-RM OOO" and
            pe.signatures[i].serial == "02:c5:35:19:36:ab:e4:05:ac:76:02:28:a4:03:87:e8"
        )
}

rule INDICATOR_KB_CERT_08d4352185317271c1cec9d05c279af7 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "52fe4ecd6c925e89068fee38f1b9a669a70f8bab"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Retalit LLC" and
            pe.signatures[i].serial == "08:d4:35:21:85:31:72:71:c1:ce:c9:d0:5c:27:9a:f7"
        )
}

rule INDICATOR_KB_CERT_0ed8ade5d73b73dade6943d557ff87e5 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "9bbd8476bf8b62be738437af628d525895a2c9c9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rumikon LLC" and
            pe.signatures[i].serial == "0e:d8:ad:e5:d7:3b:73:da:de:69:43:d5:57:ff:87:e5"
        )
}

rule INDICATOR_KB_CERT_0ed1847a2ae5d71def1e833fddd33d38 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e611a7d4cd6bb8650e1e670567ac99d0bf24b3e8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SNAB-RESURS, OOO" and
            pe.signatures[i].serial == "0e:d1:84:7a:2a:e5:d7:1d:ef:1e:83:3f:dd:d3:3d:38"
        )
}

rule INDICATOR_KB_CERT_0292c7d574132ba5c0441d1c7ffcb805 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d0ae777a34d4f8ce6b06755c007d2d92db2a760c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TES LOGISTIKA d.o.o." and
            pe.signatures[i].serial == "02:92:c7:d5:74:13:2b:a5:c0:44:1d:1c:7f:fc:b8:05"
        )
}

rule INDICATOR_KB_CERT_028d50ae0c554b49148e82db5b1c2699 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "0abdbc13639c704ff325035439ea9d20b08bc48e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VAS CO PTY LTD" and
            pe.signatures[i].serial == "02:8d:50:ae:0c:55:4b:49:14:8e:82:db:5b:1c:26:99"
        )
}

rule INDICATOR_KB_CERT_0ca41d2d9f5e991f49b162d584b0f386 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "23250aa8e1b8ae49a64d09644db3a9a65f866957"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VB CORPORATE PTY. LTD." and
            pe.signatures[i].serial == "0c:a4:1d:2d:9f:5e:99:1f:49:b1:62:d5:84:b0:f3:86"
        )
}

rule INDICATOR_KB_CERT_1389c8373c00b792207bca20aa40aa40 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "38f65d64ac93f080b229ab83cb72619b0754fa6f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VITA-DE d.o.o." and
            pe.signatures[i].serial == "13:89:c8:37:3c:00:b7:92:20:7b:ca:20:aa:40:aa:40"
        )
}

rule INDICATOR_KB_CERT_a596fd2779e507aa466d159706fe4150 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "104c4183e248d63a6e2ad6766927b070c81afcb6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ClamAV" and
            pe.signatures[i].serial == "a5:96:fd:27:79:e5:07:aa:46:6d:15:97:06:fe:41:50"
        )
}

rule INDICATOR_KB_CERT_45d76c63929c4620ab706772f5907f82 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "67c4afae16e5e2f98fe26b4597365b3cfed68b58"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NEON CRAYON LIMITED" and
            pe.signatures[i].serial == "45:d7:6c:63:92:9c:46:20:ab:70:67:72:f5:90:7f:82"
        )
}

rule INDICATOR_KB_CERT_5029daca439511456d9ed8153703f4bc {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "9d5ded35ffd34aa78273f0ebd4d6fa1e5337ac2b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE GREEN PARTNERSHIP LTD" and
            pe.signatures[i].serial == "50:29:da:ca:43:95:11:45:6d:9e:d8:15:37:03:f4:bc"
        )
}

rule INDICATOR_KB_CERT_1c7d3f6e116554809f49ce16ccb62e84 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = ""
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "1549 LIMITED" and
            pe.signatures[i].serial == "1c:7d:3f:6e:11:65:54:80:9f:49:ce:16:cc:b6:2e:84"
        )
}

rule INDICATOR_KB_CERT_75522215406335725687af888dcdc80c {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = ""
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THEESOLUTIONS LTD" and 
            pe.signatures[i].serial == "75:52:22:15:40:63:35:72:56:87:af:88:8d:cd:c8:0c"
        )
}

rule INDICATOR_KB_CERT_768ddcf9ed8d16a6bc77451ee88dfd90 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = ""
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THEESOLUTIONS LTD" and 
            pe.signatures[i].serial == "76:8d:dc:f9:ed:8d:16:a6:bc:77:45:1e:e8:8d:fd:90"
        )
}

rule INDICATOR_KB_CERT_59e378994cf1c0022764896d826e6bb8 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "9a17d31e9191644945e920bc1e7e08fbd00b62f4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SEVA MEDICAL LTD" and
            pe.signatures[i].serial == "59:e3:78:99:4c:f1:c0:02:27:64:89:6d:82:6e:6b:b8"
        )
}

/*
rule INDICATOR_KB_CERT_033ed5eda065d1b8c91dfcf92a6c9bd8 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c91dcecb3a92a17b063059200b20f5ce251b5a95"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Python Software Foundation" and
            pe.signatures[i].serial == "03:3e:d5:ed:a0:65:d1:b8:c9:1d:fc:f9:2a:6c:9b:d8"
        )
}
*/

rule INDICATOR_KB_CERT_3d2580e89526f7852b570654efd9a8bf {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c1b4d57a36e0b6853dd38e3034edf7d99a8b73ad"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MIKL LIMITED" and
            pe.signatures[i].serial == "3d:25:80:e8:95:26:f7:85:2b:57:06:54:ef:d9:a8:bf"
        )
}

rule INDICATOR_KB_CERT_5da173eb1ac76340ac058e1ff4bf5e1b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "acb38d45108c4f0c8894040646137c95e9bb39d8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALISA LTD" and
            pe.signatures[i].serial == "5d:a1:73:eb:1a:c7:63:40:ac:05:8e:1f:f4:bf:5e:1b"
        )
}

rule INDICATOR_KB_CERT_378d5543048e583a06a0819f25bd9e85 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "cf933a629598e5e192da2086e6110ad1974f8ec3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KITTY'S LTD" and
            pe.signatures[i].serial == "37:8d:55:43:04:8e:58:3a:06:a0:81:9f:25:bd:9e:85"
        )
}

rule INDICATOR_KB_CERT_0c5396dcb2949c70fac48ab08a07338e {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "b6b24aea9e983ed6bda9586a145a7ddd7e220196"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Mozilla Corporation" and
            pe.signatures[i].serial == "0c:53:96:dc:b2:94:9c:70:fa:c4:8a:b0:8a:07:33:8e"
        )
}

rule INDICATOR_KB_CERT_fdb6f4c09a1ad69d4fd2e46bb1f54313 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "4d1bc69003b1b1c3d0b43f6c17f81d13e0846ea7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FDSMMCME" and
            pe.signatures[i].serial == "fd:b6:f4:c0:9a:1a:d6:9d:4f:d2:e4:6b:b1:f5:43:13"
        )
}

rule INDICATOR_KB_CERT_e5bf5b5c0880db96477c24c18519b9b9 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = ""
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WATWGHFC" and
            pe.signatures[i].serial == "e5:bf:5b:5c:08:80:db:96:47:7c:24:c1:85:19:b9:b9"
        )
}

rule INDICATOR_KB_CERT_00ede6cfbf9fa18337b0fdb49c1f693020 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "a99b52e0999990c2eb24d1309de7d4e522937080"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "START ARCHITECTURE LTD" and
            pe.signatures[i].serial == "00:ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20"
        )
}

rule INDICATOR_KB_CERT_4f407eb50803845cc43937823e1344c0 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "0c1ffe7df27537a3dccbde6f7a49e38c4971e852"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLOW COOKED VENTURES LTD" and
            pe.signatures[i].serial == "4f:40:7e:b5:08:03:84:5c:c4:39:37:82:3e:13:44:c0"
        )
}

rule INDICATOR_KB_CERT_20a20dfce424e6bbcc162a5fcc0972ee {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "1d25a769f7ff0694d333648acea3f18b323bc9f1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TeamViewer GmbH" and
            pe.signatures[i].serial == "20:a2:0d:fc:e4:24:e6:bb:cc:16:2a:5f:cc:09:72:ee"
        )
}

rule INDICATOR_KB_CERT_2bffef48e6a321b418041310fdb9b0d0 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c40c5157e96369ceb7e26e756f2d1372128cee7b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "A&D DOMUS LIMITED" and
            pe.signatures[i].serial == "2b:ff:ef:48:e6:a3:21:b4:18:04:13:10:fd:b9:b0:d0"
        )
}

rule INDICATOR_KB_CERT_73b60719ee57974447c68187e49969a2 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "8e50ddad9fee70441d9eb225b3032de4358718dc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIT HORIZON LIMITED" and
            pe.signatures[i].serial == "73:b6:07:19:ee:57:97:44:47:c6:81:87:e4:99:69:a2"
        )
}

rule INDICATOR_KB_CERT_2925263b65c7fe1cd47b0851cc6951e3 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "88ef10f0e160b1b4bb8f0777a012f6b30ac88ac8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "tuning buddy limited" and
            pe.signatures[i].serial == "29:25:26:3b:65:c7:fe:1c:d4:7b:08:51:cc:69:51:e3"
        )
}

rule INDICATOR_KB_CERT_4ff4eda5fa641e70162713426401f438 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "a6277cc8fce0f90a1909e6dac8b02a5115dafb40"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DUHANEY LIMITED" and
            pe.signatures[i].serial == "4f:f4:ed:a5:fa:64:1e:70:16:27:13:42:64:01:f4:38"
        )
}

rule INDICATOR_KB_CERT_04c7cdcc1698e25b493eb4338d5e2f8b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "60974f5cc654e6f6c0a7332a9733e42f19186fbb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3AN LIMITED" and
            pe.signatures[i].serial == "04:c7:cd:cc:16:98:e2:5b:49:3e:b4:33:8d:5e:2f:8b"
        )
}

rule INDICATOR_KB_CERT_4c450eccd61d334e0afb2b2d9bb1d812 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "4c450eccd61d334e0afb2b2d9bb1d812"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ANJELA KEY LIMITED" and
            pe.signatures[i].serial == "4c:45:0e:cc:d6:1d:33:4e:0a:fb:2b:2d:9b:b1:d8:12"
        )
}

rule INDICATOR_KB_CERT_0e1bacb85e77d355ea69ba0b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "6750c9224540d7606d3c82c7641f49147c1b3fd0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BULDOK LIMITED" and
            pe.signatures[i].serial == "0e:1b:ac:b8:5e:77:d3:55:ea:69:ba:0b"
        )
}

rule INDICATOR_KB_CERT_5998b4affe2adf592e6528ff800e567c {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d990d584c856bd28eab641c3c3a0f80c0b71c4d7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BEAT GOES ON LIMITED" and
            pe.signatures[i].serial == "59:98:b4:af:fe:2a:df:59:2e:65:28:ff:80:0e:56:7c"
        )
}

rule INDICATOR_KB_CERT_00b7e0cf12e4ae50dd643a24285485602f {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "744160f36ba9b0b9277c6a71bf383f1898fd6d89"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GESO LTD" and
            pe.signatures[i].serial == "00:b7:e0:cf:12:e4:ae:50:dd:64:3a:24:28:54:85:60:2f"
        )
}

rule INDICATOR_KB_CERT_767436921b2698bd18400a24b01341b6 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "871899843b5fd100466e351ca773dac44e936939"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REBROSE LEISURE LIMITED" and
            pe.signatures[i].serial == "76:74:36:92:1b:26:98:bd:18:40:0a:24:b0:13:41:b6"
        )
}

rule INDICATOR_KB_CERT_26b125e669e77a5e58db378e9816fbc3 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "900aa9e6ff07c6528ecd71400e6404682e812017"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FLOWER DELI LTD" and
            pe.signatures[i].serial == "26:b1:25:e6:69:e7:7a:5e:58:db:37:8e:98:16:fb:c3"
        )
}

rule INDICATOR_KB_CERT_29a248a77d5d4066fe5da75f32102bb5 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "1078c0ab5766a48b0d4e04e57f3ab65b68dd797f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SUN & STARZ LIMITED" and
            pe.signatures[i].serial == "29:a2:48:a7:7d:5d:40:66:fe:5d:a7:5f:32:10:2b:b5"
        )
}

rule INDICATOR_KB_CERT_3a9bdec10e00e780316baaebfe7a772c {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "981b95ffcb259862e7461bc58516d7785de91a8a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PLAN ALPHA LIMITED" and
            pe.signatures[i].serial == "3a:9b:de:c1:0e:00:e7:80:31:6b:aa:eb:fe:7a:77:2c"
        )
}

rule INDICATOR_KB_CERT_73f9819f3a1a49bac1e220d7f3e0009b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "bb04986cbd65f0994a544f197fbb26abf91228d9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jean Binquet" and
            pe.signatures[i].serial == "73:f9:81:9f:3a:1a:49:ba:c1:e2:20:d7:f3:e0:00:9b"
        )
}

rule INDICATOR_KB_CERT_0989c97804c93ec0004e2843 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "98549ae51b7208bda60b7309b415d887c385864b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shanghai Hintsoft Co., Ltd." and
            pe.signatures[i].serial == "09:89:c9:78:04:c9:3e:c0:00:4e:28:43"
        )
}

rule INDICATOR_KB_CERT_6ba32f984444ea464bea41d99a977ea8 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "ae9e65e26275d014a4a8398569af5eeddf7a472c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JIN CONSULTANCY LIMITED" and
            pe.signatures[i].serial == "6b:a3:2f:98:44:44:ea:46:4b:ea:41:d9:9a:97:7e:a8"
        )
}

rule INDICATOR_KB_CERT_4f5a9bf75da76b949645475473793a7d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "f7de21bbdf5effb0f6739d505579907e9f812e6f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EXEC CONTROL LIMITED" and
            pe.signatures[i].serial == "4f:5a:9b:f7:5d:a7:6b:94:96:45:47:54:73:79:3a:7d"
        )
}

rule INDICATOR_KB_CERT_68b050aa3d2c16f77e14a16dc8d1c1ac {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c757e09e7dc5859dbd00b0ccfdd006764c557a3d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLOW POKE LTD" and
            pe.signatures[i].serial == "68:b0:50:aa:3d:2c:16:f7:7e:14:a1:6d:c8:d1:c1:ac"
        )
}

rule INDICATOR_KB_CERT_0f2b44e398ba76c5f57779c41548607b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "cef53e9ca954d1383a8ece037925aa4de9268f3f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DIGITAL DR" and
            pe.signatures[i].serial == "0f:2b:44:e3:98:ba:76:c5:f5:77:79:c4:15:48:60:7b"
        )
}

rule INDICATOR_KB_CERT_5ad4ce116b131daf8d784c6fab2ea1f1 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "de2dad893fdd49d7c0d498c0260acfb272588a2b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ORDARA LTD" and
            pe.signatures[i].serial == "5a:d4:ce:11:6b:13:1d:af:8d:78:4c:6f:ab:2e:a1:f1"
        )
}

rule INDICATOR_KB_CERT_48ce01ac7e137f4313cc5723af817da0 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "8f594f2e0665ffd656160aac235d8c490059a9cc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ET HOMES LTD" and
            pe.signatures[i].serial == "48:ce:01:ac:7e:13:7f:43:13:cc:57:23:af:81:7d:a0"
        )
}

rule INDICATOR_KB_CERT_c7e62986c36246c64b8c9f2348141570 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "f779e06266802b395ef6d3dbfeb1cc6a0a2cfc47"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC Mail.Ru" and
            pe.signatures[i].serial == "c7:e6:29:86:c3:62:46:c6:4b:8c:9f:23:48:14:15:70"
        )
}

rule INDICATOR_KB_CERT_731d40ae3f3a1fb2bc3d8395 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "b3df816a17a25557316d181ddb9f46254d6d8ca0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "win.rar GmbH" and
            pe.signatures[i].serial == "73:1d:40:ae:3f:3a:1f:b2:bc:3d:83:95"
        )
}

rule INDICATOR_KB_CERT_00ee663737d82df09c7038a6a6693a8323 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "dc934afe82adbab8583e393568f81ab32c79aeea"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KREACIJA d.o.o." and
            pe.signatures[i].serial == "00:ee:66:37:37:d8:2d:f0:9c:70:38:a6:a6:69:3a:83:23"
        )
}

rule INDICATOR_KB_CERT_3d568325dec56abf48e72317675cacb7 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e5b21024907c9115dafccc3d4f66982c7d5641bc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Virtual Byte F-B-I" and
            pe.signatures[i].serial == "3d:56:83:25:de:c5:6a:bf:48:e7:23:17:67:5c:ac:b7"
        )
}

rule INDICATOR_KB_CERT_0232466dc95b40ec9d21d9329abfcd5d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "fb845245cfbb0ee97e76c775348caa31d74bec4c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Martin Prikryl" and
            pe.signatures[i].serial == "02:32:46:6d:c9:5b:40:ec:9d:21:d9:32:9a:bf:cd:5d"
        )
}

rule INDICATOR_KB_CERT_3533080b377f80c0ea826b2492bf767b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "2afcc4cdee842d80bf7b6406fb503957c8a09b4d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\xA8\\x9C\\xE8\\xBF\\xAA\\xD0\\x91\\xE8\\xBF\\xAA\\xD0\\x91\\xE5\\xA8\\x9C\\xE5\\x93\\xA6\\xE5\\xB0\\xBA\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xD0\\x91\\xE8\\xBF\\xAA\\xD0\\x91\\xE5\\xB0\\xBA\\xE5\\xB0\\xBA\\xE8\\xBF\\xAA\\xE5\\x93\\xA6\\xE8\\xBF\\xAA\\xE5\\x8B\\x92\\xD0\\x91\\xE5\\x8B\\x92\\xE5\\x93\\xA6\\xE5\\x8B\\x92\\xE5\\x93\\xA6\\xD0\\x91" and
            pe.signatures[i].serial == "35:33:08:0b:37:7f:80:c0:ea:82:6b:24:92:bf:76:7b"
        )
}

rule INDICATOR_KB_CERT_00b0ecd32f95f8761b8a6d5710c7f34590 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "2e25e7e8abc238b05de5e2a482e51ed324fbaa76"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\x96\\xAF\\xD0\\xA8\\xD0\\xA8\\xE5\\xBC\\x97\\xE6\\xAF\\x94\\xE5\\xBC\\x97\\xD0\\xA8\\xE6\\xAF\\x94\\xD0\\xA8\\xE5\\xBC\\x97\\xD0\\xA8\\xE5\\xB0\\x94\\xE5\\xBC\\x97\\xE5\\xBC\\x97\\xD0\\xA8\\xE5\\xB0\\x94\\xD0\\xA8\\xE6\\x96\\xAF\\xE5\\xB0\\x94\\xE5\\xBC\\x97" and
            pe.signatures[i].serial == "00:b0:ec:d3:2f:95:f8:76:1b:8a:6d:57:10:c7:f3:45:90"
        )
}

rule INDICATOR_KB_CERT_3a727248e1940c5bf91a466b29c3b9cd {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "eeeb3a616bb50138f84fc0561d883b47ac1d3d3d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x90\\x89\\xE5\\x90\\x89\\xD0\\x98\\xE5\\x90\\x89\\xD0\\x98\\xE4\\xB8\\x9D\\xE4\\xB8\\x9D" and
            pe.signatures[i].serial == "3a:72:72:48:e1:94:0c:5b:f9:1a:46:6b:29:c3:b9:cd"
        )
}

rule INDICATOR_KB_CERT_00ce40906451925405d0f6c130db461f71 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "af79bbdb4fa0724f907343e9b1945ffffb34e9b3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xD0\\xA5\\xE7\\xBB\\xB4\\xE6\\x9D\\xB0\\xE6\\x96\\xAF\\xE6\\x96\\xAF\\xE7\\xBB\\xB4\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xD0\\xA5\\xE6\\x96\\xAF\\xD0\\xA5\\xD0\\xA5\\xE6\\x96\\xAF\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE6\\x96\\xAF\\xE6\\x9D\\xB0" and
            pe.signatures[i].serial == "00:ce:40:90:64:51:92:54:05:d0:f6:c1:30:db:46:1f:71"
        )
}

rule INDICATOR_KB_CERT_00e130d3537e0b7a4dda47b4d6f95f9481 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "89f9786c8cb147b1dd7aa0eb871f51210550c6f4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE4\\xBC\\x8A\\xE6\\x96\\xAF\\xE8\\x89\\xBE\\xE4\\xBC\\x8A\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xE5\\x8B\\x92" and
            pe.signatures[i].serial == "00:e1:30:d3:53:7e:0b:7a:4d:da:47:b4:d6:f9:5f:94:81"
        )
}

rule INDICATOR_KB_CERT_4bec555c48aada75e83c09c9ad22dc7c {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "a2be2ab16e3020ddbff1ff37dbfe2d736be7a0d5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xD0\\x92\\xE5\\xB1\\x81\\xE5\\xB0\\x94\\xE5\\x90\\xBE\\xD0\\x92\\xE5\\x90\\x89\\xE5\\xB0\\x94\\xE5\\x90\\xBE\\xD0\\x92\\xE4\\xB8\\x9D\\xE5\\xB1\\x81" and
            pe.signatures[i].serial == "4b:ec:55:5c:48:aa:da:75:e8:3c:09:c9:ad:22:dc:7c"
        )
}

rule INDICATOR_KB_CERT_009356e0361bcf983ab14276c332f814e7 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "f8bc145719666175a2bb3fcc62e0f3b2deccb030"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xE5\\x90\\x89\\xE4\\xB8\\x9D\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE4\\xB8\\x9D\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A\\xE6\\x9D\\xB0\\xE5\\x90\\x89\\xE4\\xBC\\x8A" and
            pe.signatures[i].serial == "00:93:56:e0:36:1b:cf:98:3a:b1:42:76:c3:32:f8:14:e7"
        )
}

rule INDICATOR_KB_CERT_00e5d20477e850c9f35c5c47123ef34271 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d11431836db24dcc3a17de8027ab284a035f2e4f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xD0\\x92\\xE5\\xBE\\xB7\\xE8\\x89\\xBE\\xE5\\x8B\\x92\\xD0\\x92\\xE8\\xB4\\x9D\\xE8\\x89\\xBE\\xE5\\xBE\\xB7\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92\\xE8\\xB4\\x9D\\xE5\\x8B\\x92\\xD0\\x92\\xE5\\xBE\\xB7\\xE8\\xB4\\x9D\\xD0\\x92\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92" and
            pe.signatures[i].serial == "00:e5:d2:04:77:e8:50:c9:f3:5c:5c:47:12:3e:f3:42:71"
        )
}

rule INDICATOR_KB_CERT_00c865d49345f1ed9a84bea40743cdf1d7 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d5e8afa85c6bf68d31af4a04668c3391e48b24b7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\xB0\\x94\\xE5\\x93\\xA6\\xD0\\x93\\xE8\\x89\\xBE\\xE5\\xB1\\x81\\xE5\\xB1\\x81\\xE5\\x93\\xA6\\xE5\\xB1\\x81\\xE5\\x93\\xA6\\xE7\\xBB\\xB4\\xE5\\x93\\xA6\\xE8\\x89\\xBE\\xE5\\xB0\\x94\\xE8\\x89\\xBE" and
            pe.signatures[i].serial == "00:c8:65:d4:93:45:f1:ed:9a:84:be:a4:07:43:cd:f1:d7"
        )
}

rule INDICATOR_KB_CERT_29f2093e925b7fe70a9ba7b909415251 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "f9fc647988e667ec92bdf1043ea1077da8f92ccc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xD0\\x99\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A\\xE5\\x85\\x8B\\xD0\\x99\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x99\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xE4\\xB8\\x9D\\xD0\\x99\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xD0\\x9D\\xE8\\x89\\xBE\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A" and
            pe.signatures[i].serial == "29:f2:09:3e:92:5b:7f:e7:0a:9b:a7:b9:09:41:52:51"
        )
}

rule INDICATOR_KB_CERT_0889e4181e71b16c4a810bee38a78419 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "bce3c17815ec9f720ba9c59126ae239c9caf856d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x8B\\x92\\xE5\\xBC\\x97\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE5\\x90\\xBE\\xE4\\xBC\\x8A\\xE5\\x90\\xBE" and
            pe.signatures[i].serial == "08:89:e4:18:1e:71:b1:6c:4a:81:0b:ee:38:a7:84:19"
        )
}

rule INDICATOR_KB_CERT_00c1afabdaa1321f815cdbb9467728bc08 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e9c5fb9a7d3aba4b49c41b45249ed20c870f5c9e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xD0\\x92\\xD0\\x93\\xE5\\x84\\xBF\\xD0\\x93\\xE5\\x8B\\x92\\xD0\\x92\\xE5\\x8B\\x92\\xD0\\x93\\xD0\\x93\\xE5\\x84\\xBF\\xE8\\x89\\xBE\\xD0\\x92\\xD0\\x93\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xD0\\x92\\xD0\\x93\\xE8\\x89\\xBE\\xE9\\xA9\\xAC\\xD0\\x93\\xE8\\x89\\xBE\\xE9\\xA9\\xAC\\xD0\\x93" and
            pe.signatures[i].serial == "00:c1:af:ab:da:a1:32:1f:81:5c:db:b9:46:77:28:bc:08"
        )
}

rule INDICATOR_KB_CERT_371381a66fb96a07077860ae4a6721e1 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c4419f095ae93d93e145d678ed31459506423d6a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE7\\xBB\\xB4\\xD0\\xA9\\xE5\\x90\\xBE\\xE7\\xBB\\xB4\\xD0\\xA9\\xD0\\xA9\\xE7\\xBB\\xB4\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xD0\\xA9\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xD0\\xA9\\xE5\\xA8\\x9C\\xE6\\x9D\\xB0\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xE5\\xA8\\x9C\\xE5\\xA8\\x9C\\xD0\\xA9" and
            pe.signatures[i].serial == "37:13:81:a6:6f:b9:6a:07:07:78:60:ae:4a:67:21:e1"
        )
}

rule INDICATOR_KB_CERT_0deb004e56d7fcec1caa8f2928d4e768 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "21dacc55b6e0b3b0e761be03ed6edd713489b6ce"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC Mail.Ru" and
            pe.signatures[i].serial == "0d:eb:00:4e:56:d7:fc:ec:1c:aa:8f:29:28:d4:e7:68"
        )
}

rule INDICATOR_KB_CERT_7bd36898217b4cc6b6427dd7c361e43d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c55df31aa16adb1013612ceb1dcf587afb7832c3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aeafefcafbafbaf" and
            pe.signatures[i].serial == "7b:d3:68:98:21:7b:4c:c6:b6:42:7d:d7:c3:61:e4:3d"
        )
}

rule INDICATOR_KB_CERT_02d17fbf4869f23fea43c7863902df93 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d336ff8d8ccb771943a70bb4ba11239fb71beca5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Windows" and
            pe.signatures[i].serial == "02:d1:7f:bf:48:69:f2:3f:ea:43:c7:86:39:02:df:93"
        )
}

rule INDICATOR_KB_CERT_1e74cfe7de8c5f57840a61034414ca9f {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "2dfa711a12aed0ace72e538c57136fa021412f95951c319dcb331a3e529cf86e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Insta Software Solution Inc." and
            pe.signatures[i].serial == "1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f"
        )
}

rule INDICATOR_KB_CERT_009272607cfc982b782a5d36c4b78f5e7b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "2514c615fe54d511555bc5b57909874e48a438918a54cea4a0b3fbc401afa127"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rada SP Z o o" and
            pe.signatures[i].serial == "00:92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b"
        )
}

rule INDICATOR_KB_CERT_7b91468122273aa32b7cfc80c331ea13 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "409f32dc91542546e7c7f85f687fe3f1acffdd853657c8aa8c1c985027f5271d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO KBI" and
            pe.signatures[i].serial == "7b:91:46:81:22:27:3a:a3:2b:7c:fc:80:c3:31:ea:13"
        )
}

rule INDICATOR_KB_CERT_0082cb93593b658100cdd7a00c874287f2 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d168d7cf7add6001df83af1fc603a459e11395a9077579abcdfd708ad7b7271f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sportsonline24 B.V." and
            pe.signatures[i].serial == "00:82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2"
        )
}

rule INDICATOR_KB_CERT_00df683d46d8c3832489672cc4e82d3d5d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "8b63c5ea8d9e4797d77574f35d1c2fdff650511264b12ce2818c46b19929095b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Osatokio Oy" and
            pe.signatures[i].serial == "00:df:68:3d:46:d8:c3:83:24:89:67:2c:c4:e8:2d:3d:5d"
        )
}

rule INDICATOR_KB_CERT_105440f57e9d04419f5a3e72195110e6 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e95c7b4f2e5f64b388e968d0763da67014eb3aeb8c04bd44333ca3e151aa78c2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CRYPTOLAYER SRL" and
            pe.signatures[i].serial == "10:54:40:f5:7e:9d:04:41:9f:5a:3e:72:19:51:10:e6"
        )
}

rule INDICATOR_KB_CERT_c01e41ff29078e6626a640c5a19a8d80 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "cca4a461592e6adff4e0a4458ebe29ee4de5f04c638dbd3b7ee30f3519cfd7e5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BurnAware" and
            pe.signatures[i].serial == "c0:1e:41:ff:29:07:8e:66:26:a6:40:c5:a1:9a:8d:80"
        )
}

rule INDICATOR_KB_CERT_00fa3dcac19b884b44ef4f81541184d6b0 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "6557117e37296d7fdcac23f20b57e3d52cabdb8e5aa24d3b78536379d57845be"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unicom Ltd" and
            pe.signatures[i].serial == "00:fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0"
        )
}

rule INDICATOR_KB_CERT_70e1ebd170db8102d8c28e58392e5632 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "90d67006be03f2254e1da76d4ea7dc24372c4f30b652857890f9d9a391e9279c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Equal Cash Technologies Limited" and
            pe.signatures[i].serial == "70:e1:eb:d1:70:db:81:02:d8:c2:8e:58:39:2e:56:32"
        )
}

rule INDICATOR_KB_CERT_6cfa5050c819c4acbb8fa75979688dff {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e7241394097402bf9e32c87cada4ba5e0d1e9923f028683713c2f339f6f59fa9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Elite Web Development Ltd." and
            pe.signatures[i].serial == "6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff"
        )
}

rule INDICATOR_KB_CERT_00b8164f7143e1a313003ab0c834562f1f {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "263c636c5de68f0cd2adf31b7aebc18a5e00fc47a5e2124e2a5613b9a0247c1e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ekitai Data Inc." and
            pe.signatures[i].serial == "00:b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f"
        )
}

rule INDICATOR_KB_CERT_e3c7cc0950152e9ceead4304d01f6c89 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "82975e3e21e8fd37bb723de6fdb6e18df9d0e55f0067cc77dd571a52025c6724"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DNS KOMPLEKT" and
            pe.signatures[i].serial == "e3:c7:cc:09:50:15:2e:9c:ee:ad:43:04:d0:1f:6c:89"
        )
}

rule INDICATOR_KB_CERT_6a241ffe96a6349df608d22c02942268 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f97f4b9953124091a5053712b2c22b845b587cb2655156dcafed202fa7ceeeb1"    
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HELP, d.o.o." and
            pe.signatures[i].serial == "6a:24:1f:fe:96:a6:34:9d:f6:08:d2:2c:02:94:22:68"
        )
}

rule INDICATOR_KB_CERT_00c04f5d17af872cb2c37e3367fe761d0d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7f52ece50576fcc7d66e028ecec89d3faedeeedb953935e215aac4215c9f4d63"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DES SP Z O O" and
            (
                pe.signatures[i].serial == "00:c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d" or
                pe.signatures[i].serial == "c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d"    
            )
        )
}

rule INDICATOR_KB_CERT_5c7e78f53c31d6aa5b45de14b47eb5c4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f91d436c1c7084b83007f032ef48fecda382ff8b81320212adb81e462976ad5a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cubic Information Systems, UAB" and
            pe.signatures[i].serial == "5c:7e:78:f5:3c:31:d6:aa:5b:45:de:14:b4:7e:b5:c4"
        )
}

rule INDICATOR_KB_CERT_7156ec47ef01ab8359ef4304e5af1a05 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "59fe580974e2f813c2a00b4be01acd46c94fdea89a3049433cd5ba5a2d96666d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BOREC, OOO" and
            pe.signatures[i].serial == "71:56:ec:47:ef:01:ab:83:59:ef:43:04:e5:af:1a:05"
        )
}

rule INDICATOR_KB_CERT_00b2e730b0526f36faf7d093d48d6d9997 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "10dd41eb9225b615e6e4f1dce6690bd2c8d055f07d4238db902f3263e62a04a9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bamboo Connect s.r.o." and
            pe.signatures[i].serial == "00:b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97"
        )
}

rule INDICATOR_KB_CERT_2c90eaf4de3afc03ba924c719435c2a3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6b916111ffbd6736afa569d7d940ada544daf3b18213a0da3025b20973a577dc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AntiFIX s.r.o." and
            pe.signatures[i].serial == "2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3"
        )
}

rule INDICATOR_KB_CERT_00bdc81bc76090dae0eee2e1eb744a4f9a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a3b0a1cd3998688f294838758688f96adee7d5aa98ec43709b8868d6914e96c1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALM4U GmbH" and
            pe.signatures[i].serial == "00:bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a"
        )
}

rule INDICATOR_KB_CERT_00e38259cf24cc702ce441b683ad578911 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "16304d4840d34a641f58fe7c94a7927e1ba4b3936638164525bedc5a406529f8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Akhirah Technologies Inc." and
            pe.signatures[i].serial == "00:e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11"
        )
}

rule INDICATOR_KB_CERT_4929ab561c812af93ddb9758b545f546 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0946bf998f8a463a1c167637537f3eba35205b748efc444a2e7f935dc8dd6dc7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Everything Wow s.r.o." and
            pe.signatures[i].serial == "49:29:ab:56:1c:81:2a:f9:3d:db:97:58:b5:45:f5:46"
        )
}

rule INDICATOR_KB_CERT_00b649a966410f62999c939384af553919 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a0c6cd25e1990c0d03b6ec1ad5a140f2c8014a8c2f1f4f227ee2597df91a8b6c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "F.A.T. SARL" and
            pe.signatures[i].serial == "00:b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19"
        )
}

rule INDICATOR_KB_CERT_22367dbefd0a325c3893af52547b14fa {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b5cb5b256e47a30504392c37991e4efc4ce838fde4ad8df47456d30b417e6d5c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "F.lux Software LLC" and
            pe.signatures[i].serial == "22:36:7d:be:fd:0a:32:5c:38:93:af:52:54:7b:14:fa"
        )
}

rule INDICATOR_KB_CERT_00e04a344b397f752a45b128a594a3d6b5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d73229f3b7c2025a5a56e6e189be8a9120f1b3b0d8a78b7f62eff5c8d2293330"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Highweb Ireland Operations Limited" and
            pe.signatures[i].serial == "00:e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5"
        )
}

rule INDICATOR_KB_CERT_00a7989f8be0c82d35a19e7b3dd4be30e5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3e93aadb509b542c065801f04cffb34956f84ee8c322d65c7ae8e23d27fe5fbf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Instamix Limited" and
            pe.signatures[i].serial == "00:a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5"
        )
}

rule INDICATOR_KB_CERT_39f56251df2088223cc03494084e6081 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "66f32cf78b8f685a2c6f5bf361c9b0f9a9678de11a8e7931e2205d0ef65af05c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Inter Med Pty. Ltd." and
            pe.signatures[i].serial == "39:f5:62:51:df:20:88:22:3c:c0:34:94:08:4e:60:81"
        )
}

rule INDICATOR_KB_CERT_009cfbb4c69008821aaacecde97ee149ab {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6c7e917a2cc2b2228d6d4a0556bda6b2db9f06691749d2715af9a6a283ec987b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kivaliz Prest s.r.l." and
            pe.signatures[i].serial == "00:9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab"
        )
}

rule INDICATOR_KB_CERT_008cff807edaf368a60e4106906d8df319 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c97d809c73f376cdf8062329b357b16c9da9d14261895cd52400f845a2d6bdb1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KRAFT BOKS OOO" and
            pe.signatures[i].serial == "00:8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19"
        )
}

rule INDICATOR_KB_CERT_2924785fd7990b2d510675176dae2bed {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "adbc44fda783b5fa817f66147d911fb81a0e2032a1c1527d1b3adbe55f9d682d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Neoopt LLC" and
            pe.signatures[i].serial == "29:24:78:5f:d7:99:0b:2d:51:06:75:17:6d:ae:2b:ed"
        )
}

rule INDICATOR_KB_CERT_f2c4b99487ed33396d77029b477494bc {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f38abffd259919d68969b8b2d265afac503a53dd"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bedaabaefadfdfedcbbbebaaef" and
            pe.signatures[i].serial == "f2:c4:b9:94:87:ed:33:39:6d:77:02:9b:47:74:94:bc"
        )
}

rule INDICATOR_KB_CERT_c54cccff8acceb9654b6f585e2442ef7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "416c79fccc5f42260cd227fd831b001aca14bf0d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eadbebdebcc" and
            pe.signatures[i].serial == "c5:4c:cc:ff:8a:cc:eb:96:54:b6:f5:85:e2:44:2e:f7"
        )
}

rule INDICATOR_KB_CERT_690910dc89d7857c3500fb74bed2b08d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "dfeb986812ba9f2af6d4ff94c5d1128fa50787951c07b4088f099a5701f1a1a4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OLIMP STROI" and
            pe.signatures[i].serial == "69:09:10:dc:89:d7:85:7c:35:00:fb:74:be:d2:b0:8d"
        )
}

rule INDICATOR_KB_CERT_0af9b523180f34a24fcfd11b74e7d6cd {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c8aec622951068734d754dc2efd7032f9ac572e26081ac38b8ceb333ccc165c9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ORBIS LTD" and
            pe.signatures[i].serial == "0a:f9:b5:23:18:0f:34:a2:4f:cf:d1:1b:74:e7:d6:cd"
        )
}

rule INDICATOR_KB_CERT_00f4d2def53bccb0dd2b7d54e4853a2fc5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d5431403ba7b026666e72c675aac6c46720583a60320c5c2c0f74331fe845c35"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PETROYL GROUP, TOV" and
            pe.signatures[i].serial == "00:f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5"
        )
}

rule INDICATOR_KB_CERT_56d576a062491ea0a5877ced418203a1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b22e022f030cf1e760a7df84d22e78087f3ea2ed262a4b76c8b133871c58213b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Silvo LLC" and
            pe.signatures[i].serial == "56:d5:76:a0:62:49:1e:a0:a5:87:7c:ed:41:82:03:a1"
        )
}

rule INDICATOR_KB_CERT_4152169f22454ed604d03555b7afb175 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a1561cacd844fcb62e9e0a8ee93620b3b7d4c3f4bd6f3d6168129136471a7fdb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SMACKTECH SOFTWARE LIMITED" and
            pe.signatures[i].serial == "41:52:16:9f:22:45:4e:d6:04:d0:35:55:b7:af:b1:75"
        )
}

rule INDICATOR_KB_CERT_41d05676e0d31908be4dead3486aeae3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e6e597527853ee64b45d48897e3ca4331f6cc08a88cc57ff2045923e65461598"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rov SP Z O O" and
            pe.signatures[i].serial == "41:d0:56:76:e0:d3:19:08:be:4d:ea:d3:48:6a:ea:e3"
        )
}

rule INDICATOR_KB_CERT_13c7b92282aae782bfb00baf879935f4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c253cce2094c0a4ec403518d4fbf18c650e5434759bc690758cb3658b75c8baa"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and
            pe.signatures[i].serial == "13:c7:b9:22:82:aa:e7:82:bf:b0:0b:af:87:99:35:f4"
        )
}

rule INDICATOR_KB_CERT_00d627f1000d12485995514bfbdefc55d9 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5fac3a6484e93f62686e12de3611f7a5251009d541f65e8fe17decc780148052"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THREE D CORPORATION PTY LTD" and
            pe.signatures[i].serial == "00:d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9"
        )
}

rule INDICATOR_KB_CERT_62205361a758b00572d417cba014f007 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "83e851e8c50f9d7299363181f2275edc194037be8cb6710762d2099e0b3f31c6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UNITEKH-S, OOO" and
            pe.signatures[i].serial == "62:20:53:61:a7:58:b0:05:72:d4:17:cb:a0:14:f0:07"
        )
}

rule INDICATOR_KB_CERT_566ac16a57b132d3f64dced14de790ee {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2e44464a5907ac46981bebd8eed86d8deec9a4cfafdf1652c8ba68551d4443ff"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unirad LLC" and
            pe.signatures[i].serial == "56:6a:c1:6a:57:b1:32:d3:f6:4d:ce:d1:4d:e7:90:ee"
        )
}

rule INDICATOR_KB_CERT_661ba8f3c9d1b348413484e9a49502f7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4ca944c9b69f72be3e95f385bdbc70fc7cff4c3ebb76a365bf0ab0126b277b2d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unique Digital Services Ltd." and
            pe.signatures[i].serial == "66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7"
        )
}

rule INDICATOR_KB_CERT_0092d9b92f8cf7a1ba8b2c025be730c300 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b891c96bd8548c60fa86b753f0c4a4ccc7ab51256b4ee984b5187c62470f9396"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UPLagga Systems s.r.o." and
            pe.signatures[i].serial == "00:92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00"
        )
}

rule INDICATOR_KB_CERT_00e5ad42c509a7c24605530d35832c091e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "17b1f6ffc569acd2cf803c4ac24a7f9828d8d14f6b057e65efdb5c93cc729351"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VESNA, OOO" and
            pe.signatures[i].serial == "00:e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e"
        )
}

rule INDICATOR_KB_CERT_3e57584db26a2c2ebc24ae3e1954fff6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4ecbada12a11a5ad5fe6a72a8baaf9d67dc07556a42f6e9a9b6765e334099f4e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Zaryad LLC" and
            pe.signatures[i].serial == "3e:57:58:4d:b2:6a:2c:2e:bc:24:ae:3e:19:54:ff:f6"
        )
}

rule INDICATOR_KB_CERT_13794371c052ec0559e9b492abb25c26 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "dd3ab539932e81db45cf262d44868e1f0f88a7b0baf682fb89d1a3fcfba3980b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Carmel group LLC" and
            pe.signatures[i].serial == "13:79:43:71:c0:52:ec:05:59:e9:b4:92:ab:b2:5c:26"
        )
}

rule INDICATOR_KB_CERT_51aead5a9ab2d841b449fa82de3a8a00 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "155edd03d034d6958af61bc6a7181ef8f840feae68a236be3ff73ce7553651b0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Corsair Software Solution Inc." and
            pe.signatures[i].serial == "51:ae:ad:5a:9a:b2:d8:41:b4:49:fa:82:de:3a:8a:00"
        )
}

rule INDICATOR_KB_CERT_bce1d49ff444d032ba3dda6394a311e9 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e9a9ef5dfca4d2e720e86443c6d491175f0e329ab109141e6e2ee4f0e33f2e38"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DECIPHER MEDIA LLC" and
            pe.signatures[i].serial == "bc:e1:d4:9f:f4:44:d0:32:ba:3d:da:63:94:a3:11:e9"
        )
}

rule INDICATOR_KB_CERT_00dadf44e4046372313ee97b8e394c4079 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "80986ae0d4f8c8fabf6c4a91550c90224e26205a4ca61c00ff6736dd94817e65"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digital Capital Management Ireland Limited" and
            pe.signatures[i].serial == "00:da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79"
        )
}

rule INDICATOR_KB_CERT_00f8c2e08438bb0e9adc955e4b493e5821 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "459ef82eb5756e85922a4687d66bd6a0195834f955ede35ae6c3039d97b00b5f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DocsGen Software Solutions Inc." and
            pe.signatures[i].serial == "00:f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21"
        )
}

rule INDICATOR_KB_CERT_00d2caf7908aaebfa1a8f3e2136fece024 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "82baf9b781d458a29469e5370bc9752ebef10f3f8ea506ca6dd04ea5d5f70334"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FANATOR, OOO" and
            pe.signatures[i].serial == "00:d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24"
        )
}

rule INDICATOR_KB_CERT_003223b4616c2687c04865bee8321726a8 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "321218e292c2c489bbc7171526e1b4e02ef68ce23105eee87832f875b871ed9f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and
            pe.signatures[i].serial == "32:23:b4:61:6c:26:87:c0:48:65:be:e8:32:17:26:a8"
        )
}

rule INDICATOR_KB_CERT_0fa13ae98e17ae23fcfe7ae873d0c120 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "be226576c113cd14bcdb67e46aab235d9257cd77b826b0d22a9aa0985bad5f35"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KLAKSON, LLC" and
            pe.signatures[i].serial == "0f:a1:3a:e9:8e:17:ae:23:fc:fe:7a:e8:73:d0:c1:20"
        )
}

rule INDICATOR_KB_CERT_3696883055975d571199c6b5d48f3cd5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "933749369d61bebd5f2c63ff98625973c41098462d9732cffaffe7e02823bc3a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Korist Networks Incorporated" and
            pe.signatures[i].serial == "36:96:88:30:55:97:5d:57:11:99:c6:b5:d4:8f:3c:d5"
        )
}

rule INDICATOR_KB_CERT_00aff762e907f0644e76ed8a7485fb12a1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7b0c55ae9f8f5d82edbc3741ea633ae272bbb2207da8e88694e06d966d86bc63"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lets Start SP Z O O" and
            pe.signatures[i].serial == "00:af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1"
        )
}

rule INDICATOR_KB_CERT_5b440a47e8ce3dd202271e5c7a666c78 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "07e4cbdd52027e38b86727e88b33a0a1d49fe18f5aee4101353dd371d7a28da5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Master Networking s.r.o." and
            pe.signatures[i].serial == "5b:44:0a:47:e8:ce:3d:d2:02:27:1e:5c:7a:66:6c:78"
        )
}

rule INDICATOR_KB_CERT_00fe41941464b9992a69b7317418ae8eb7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ef4da71810fb92e942446ee1d9b5f38fea49628e0d8335a485f328fcef7f1a20"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Milsean Software Limited" and
            pe.signatures[i].serial == "00:fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7"
        )
}

rule INDICATOR_KB_CERT_29128a56e7b3bfb230742591ac8b4718 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f9fcc798e1fccee123034fe9da9a28283de48ba7ae20f0c55ce0d36ae4625133"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Programavimo paslaugos, MB" and
            pe.signatures[i].serial == "29:12:8a:56:e7:b3:bf:b2:30:74:25:91:ac:8b:47:18"
        )
}

rule INDICATOR_KB_CERT_00c2bb11cfc5e80bf4e8db2ed0aa7e50c5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f1044e01ff30d14a3f6c89effae9dbcd2b43658a3f7885c109f6e22af1a8da4b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rooth Media Enterprises Limited" and
            pe.signatures[i].serial == "00:c2:bb:11:cf:c5:e8:0b:f4:e8:db:2e:d0:aa:7e:50:c5"
        )
}

rule INDICATOR_KB_CERT_040cc2255db4e48da1b4f242f5edfa73 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1270a79829806834146ef50a8036cfcc1067e0822e400f81073413a60aa9ed54"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Softland SRL" and
            pe.signatures[i].serial == "04:0c:c2:25:5d:b4:e4:8d:a1:b4:f2:42:f5:ed:fa:73"
        )
}

rule INDICATOR_KB_CERT_3bcaed3ef678f2f9bf38d09e149b8d70 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "45d598691e79be3c47e1883d4b0e149c13a76932ea630be429b0cfccf3217bc2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "StarY Media Inc." and
            pe.signatures[i].serial == "3b:ca:ed:3e:f6:78:f2:f9:bf:38:d0:9e:14:9b:8d:70"
        )
}

rule INDICATOR_KB_CERT_091736d368a5980ebeb433a0ecb49fbb {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b1c1dc94f0c775deeb46a0a019597c4ac27ab2810e3b3241bdc284d2fccf3eb5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ELEKSIR, OOO" and
            pe.signatures[i].serial == "09:17:36:d3:68:a5:98:0e:be:b4:33:a0:ec:b4:9f:bb"
        )
}

rule INDICATOR_KB_CERT_00e48cb3314977d77dedcd4c77dd144c50 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "025bce0f36ec5bac08853966270ed2f5e28765d9c398044462a28c67d74d71e1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BESPOKE SOFTWARE SOLUTIONS LIMITED" and
            pe.signatures[i].serial == "00:e4:8c:b3:31:49:77:d7:7d:ed:cd:4c:77:dd:14:4c:50"
        )
}

rule INDICATOR_KB_CERT_1e72a72351aecf884df9cdb77a16fd84 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f945bbea1c2e2dd4ed17f5a98ea7c0f0add6bfc3d07353727b40ce48a7d5e48f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Buket and Co." and
            pe.signatures[i].serial == "1e:72:a7:23:51:ae:cf:88:4d:f9:cd:b7:7a:16:fd:84"
        )
}

rule INDICATOR_KB_CERT_00b383658885e271129a43d19de40c1fc6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ef234051b4b83086b675ff58aca85678544c14da39dbdf4d4fa9d5f16e654e2f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Elekon" and
            pe.signatures[i].serial == "00:b3:83:65:88:85:e2:71:12:9a:43:d1:9d:e4:0c:1f:c6"
        )
}

rule INDICATOR_KB_CERT_00ca7d54577243934f665fd1d443855a3d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2ea2c7625c1a42fff63f0b17cfc4fd0c0f76d7eb45a86b18ec9a630d3d8ad913"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FABO SP Z O O" and
            pe.signatures[i].serial == "00:ca:7d:54:57:72:43:93:4f:66:5f:d1:d4:43:85:5a:3d"
        )
}

rule INDICATOR_KB_CERT_7709d2df39e9a4f7db2f3cbc29b49743 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "04349ba0f4d74f46387cee8a13ee72ab875032b4396d6903a6e9e7f047426de8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Grina LLC" and
            pe.signatures[i].serial == "77:09:d2:df:39:e9:a4:f7:db:2f:3c:bc:29:b4:97:43"
        )
}

rule INDICATOR_KB_CERT_186d49fac34ce99775b8e7ffbf50679d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "812a80556775d658450362e1b3650872b91deba44fef28f17c9364add5aa398e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hairis LLC" and
            pe.signatures[i].serial == "18:6d:49:fa:c3:4c:e9:97:75:b8:e7:ff:bf:50:67:9d"
        )
}

rule INDICATOR_KB_CERT_0097df46acb26b7c81a13cc467b47688c8 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "54c4929195fafddfd333871471a015fa68092f44e2f262f2bbf4ee980b41b809"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Information Civilized System Oy" and
            pe.signatures[i].serial == "00:97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8"
        )
}

rule INDICATOR_KB_CERT_2a52acb34bd075ac9f58771d2a4bbfba {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c839065a159bec7e63bfdcb1794889829853c07f7a931666f4eb84103302c1c9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Katarzyna Galganek mim e coc" and
            pe.signatures[i].serial == "2a:52:ac:b3:4b:d0:75:ac:9f:58:77:1d:2a:4b:bf:ba"
        )
}

rule INDICATOR_KB_CERT_5a9d897077a22afe7ad4c4a01df6c418 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "50fa9d22557354a078767cb61f93de9abe491e3a8cb69c280796c7c20eabd5b9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Klarens LLC" and
            pe.signatures[i].serial == "5a:9d:89:70:77:a2:2a:fe:7a:d4:c4:a0:1d:f6:c4:18"
        )
}

rule INDICATOR_KB_CERT_00d7c432e8d4edef515bfb9d1c214ff0f5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6256d3ca79330f7bd912a88e59f9a4f3bdebdcd6b9c55cda4e733e26583b3d61"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC \"MILKY PUT\"" and
            pe.signatures[i].serial == "00:d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5"
        )
}

rule INDICATOR_KB_CERT_0085e1af2be0f380e5a5d11513ddf45fc6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e9849101535b47ff2a67e4897113c06f024d33f575baa5b426352f15116b98b4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Makke Digital Works" and
            pe.signatures[i].serial == "00:85:e1:af:2b:e0:f3:80:e5:a5:d1:15:13:dd:f4:5f:c6"
        )
}

rule INDICATOR_KB_CERT_02aa497d39320fc979ad96160d90d410 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "33e8e72a75d6f424c5a10d2b771254c07a7d9c138e5fea703117fe60951427ae"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MATCHLESS GIFTS, INC." and
            pe.signatures[i].serial == "02:aa:49:7d:39:32:0f:c9:79:ad:96:16:0d:90:d4:10"
        )
}

rule INDICATOR_KB_CERT_d0b094274c761f367a8eaea08e1d9c8f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e94a9d81c4a67ef953fdb27aad6ec8fa347e6903b140d21468066bdca8925bc5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nsasoft US LLC" and
            pe.signatures[i].serial == "d0:b0:94:27:4c:76:1f:36:7a:8e:ae:a0:8e:1d:9c:8f"
        )
}

rule INDICATOR_KB_CERT_00d59a05955a4a421500f9561ce983aac4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7f56555ac8479d4e130a89e787b7ff2f47005cc02776cf7a30a58611748c4c2e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Olymp LLC" and
            pe.signatures[i].serial == "00:d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4"
        )
}

rule INDICATOR_KB_CERT_35590ebe4a02dc23317d8ce47a947a9b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d9b60a67cf3c8964be1e691d22b97932d40437bfead97a84c1350a2c57914f28"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Largos" and
            pe.signatures[i].serial == "35:59:0e:be:4a:02:dc:23:31:7d:8c:e4:7a:94:7a:9b"
        )
}

rule INDICATOR_KB_CERT_1f23f001458716d435cca1a55d660ec5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "934d9357b6fb96f7fb8c461dd86824b3eed5f44a65c10383fe0be742c8c9b60e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Ringen" and
            pe.signatures[i].serial == "1f:23:f0:01:45:87:16:d4:35:cc:a1:a5:5d:66:0e:c5"
        )
}

rule INDICATOR_KB_CERT_00c2fc83d458e653837fcfc132c9b03062 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "82294a7efa5208eb2344db420b9aeff317337a073c1a6b41b39dda549a94557e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Vertical" and
            pe.signatures[i].serial == "00:c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62"
        )
}

rule INDICATOR_KB_CERT_fcb3d3519e66e5b6d90b8b595f558e81 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8bf6e51dfe209a2ca87da4c6b61d1e9a92e336e1a83372d7a568132af3ad0196"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pegasun" and
            pe.signatures[i].serial == "fc:b3:d3:51:9e:66:e5:b6:d9:0b:8b:59:5f:55:8e:81"
        )
}

rule INDICATOR_KB_CERT_4b03cabe6a0481f17a2dbeb9aefad425 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2e86cb95aa7e4c1f396e236b41bb184787274bb286909b60790b98f713b58777"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RASSVET, OOO" and
            pe.signatures[i].serial == "4b:03:ca:be:6a:04:81:f1:7a:2d:be:b9:ae:fa:d4:25"
        )
}

rule INDICATOR_KB_CERT_539015999e304a5952985a994f9c3a53 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7731825aea38cfc77ba039a74417dd211abef2e16094072d8c2384af1093f575"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Service lab LLC" and
            pe.signatures[i].serial == "53:90:15:99:9e:30:4a:59:52:98:5a:99:4f:9c:3a:53"
        )
}

rule INDICATOR_KB_CERT_016836311fc39fbb8e6f308bb03cc2b3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "cab373e2d4672beacf4ca9c9baf75a2182a106cca5ea32f2fc2295848771a979"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SERVICE STREAM LIMITED" and
            pe.signatures[i].serial == "01:68:36:31:1f:c3:9f:bb:8e:6f:30:8b:b0:3c:c2:b3"
        )
}

rule INDICATOR_KB_CERT_009bd81a9adaf71f1ff081c1f4a05d7fd7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "885b9f1306850a87598e5230fcae71282042b74e8a14cabb0a904c559b506acb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SMART TOYS AND GAMES" and
            pe.signatures[i].serial == "00:9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7"
        )
}

rule INDICATOR_KB_CERT_082023879112289bf351d297cc8efcfc {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0eb3382177f26e122e44ddd74df262a45ebe8261029bc21b411958a07b06278a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STA-R TOV" and
            pe.signatures[i].serial == "08:20:23:87:91:12:28:9b:f3:51:d2:97:cc:8e:fc:fc"
        )
}

rule INDICATOR_KB_CERT_00ece6cbf67dc41635a5e5d075f286af23 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f1f83c96ab00dcb70c0231d946b6fbd6a01e2c94e8f9f30352bbe50e89a9a51c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THRANE AGENTUR ApS" and
            pe.signatures[i].serial == "00:ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23"
        )
}

rule INDICATOR_KB_CERT_5fb6bae8834edd8d3d58818edc86d7d7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "026868bbc22c6a37094851e0c6f372da90a8776b01f024badb03033706828088"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tramplink LLC" and
            pe.signatures[i].serial == "5f:b6:ba:e8:83:4e:dd:8d:3d:58:81:8e:dc:86:d7:d7"
        )
}

rule INDICATOR_KB_CERT_6e0ccbdfb4777e10ea6221b90dc350c2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "367b3092fbcd132efdbebabdc7240e29e3c91366f78137a27177315d32a926b9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TRAUMALAB INTERNATIONAL APS" and
            pe.signatures[i].serial == "6e:0c:cb:df:b4:77:7e:10:ea:62:21:b9:0d:c3:50:c2"
        )
}

rule INDICATOR_KB_CERT_1249aa2ada4967969b71ce63bf187c38 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c139076033e8391c85ba05508c4017736a8a7d9c1350e6b5996dd94b374f403c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Umbrella LLC" and
            pe.signatures[i].serial == "12:49:aa:2a:da:49:67:96:9b:71:ce:63:bf:18:7c:38"
        )
}

rule INDICATOR_KB_CERT_2dcd0699da08915dde6d044cb474157c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "13bf3156e66a57d413455973866102b0a1f6d45a1e6de050ca9dcf16ecafb4e2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VENTE DE TOUT" and
            pe.signatures[i].serial == "2d:cd:06:99:da:08:91:5d:de:6d:04:4c:b4:74:15:7c"
        )
}

rule INDICATOR_KB_CERT_008d52fb12a2511e86bbb0ba75c517eab0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9e918ce337aebb755e23885d928e1a67eca6823934935010e82b561b928df2f9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VThink Software Consulting Inc." and
            pe.signatures[i].serial == "00:8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0"
        )
}

rule INDICATOR_KB_CERT_00b1aea98bf0ce789b6c952310f14edde0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "28324a9746edbdb41c9579032d6eb6ab4fd3e0906f250d4858ce9c5fe5e97469"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Absolut LLC" and
            pe.signatures[i].serial == "00:b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0"
        )
}

rule INDICATOR_KB_CERT_00f097e59809ae2e771b7b9ae5fc3408d7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "22ad7df275c8b5036ea05b95ce5da768049bd2b21993549eed3a8a5ada990b1e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABEL RENOVATIONS, INC." and
            pe.signatures[i].serial == "00:f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7"
        )
}

rule INDICATOR_KB_CERT_2e8023a5a0328f66656e1fc251c82680 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e3eff064ad23cc4c98cdbcd78e4e5a69527cf2e4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Philippe Mantes" and
            pe.signatures[i].serial == "2e:80:23:a5:a0:32:8f:66:65:6e:1f:c2:51:c8:26:80"
        )
}

rule INDICATOR_KB_CERT_38b0eaa7c533051a456fb96c4ecf91c4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8e2e69b1202210dc9d2155a0f974ab8c325d5297"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Marianne Septier" and
            pe.signatures[i].serial == "38:b0:ea:a7:c5:33:05:1a:45:6f:b9:6c:4e:cf:91:c4"
        )
}

rule INDICATOR_KB_CERT_738db9460a10bb8bc03dc59feac3be5e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4cf77e598b603c13cdcd1a676ca61513558df746"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jocelyn Bennett" and
            pe.signatures[i].serial == "73:8d:b9:46:0a:10:bb:8b:c0:3d:c5:9f:ea:c3:be:5e"
        )
}

rule INDICATOR_KB_CERT_141d6dafed065980d97520e666493396 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "28225705d615a47de0d1b0e324b5b9ca7c11ce48"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ralph Schmidt" and
            pe.signatures[i].serial == "14:1d:6d:af:ed:06:59:80:d9:75:20:e6:66:49:33:96"
        )
}

rule INDICATOR_KB_CERT_07cf63bdccc15c55e5ce785bdfbeaacf {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3306df7607bed04187d23c1eb93adf2998e51d01"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REITSUPER ESTATE LLC" and
            pe.signatures[i].serial == "07:cf:63:bd:cc:c1:5c:55:e5:ce:78:5b:df:be:aa:cf"
        )
}

rule INDICATOR_KB_CERT_0382cd4b6ed21ed7c3eaea266269d000 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e600612ffcd002718b7d03a49d142d07c5a04154"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LOOK AND FEEL SP Z O O" and
            pe.signatures[i].serial == "03:82:cd:4b:6e:d2:1e:d7:c3:ea:ea:26:62:69:d0:00"
        )
}

rule INDICATOR_KB_CERT_08653ef2ed9e6ebb56ffa7e93f963235 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1567d022b47704a1fd7ab71ff60a121d0c1df33a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Haw Farm LIMITED" and
            pe.signatures[i].serial == "08:65:3e:f2:ed:9e:6e:bb:56:ff:a7:e9:3f:96:32:35"
        )
}

rule INDICATOR_KB_CERT_0ddce8cdc91b5b649bb4b45ffbba6c6c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "23c446940a9cdc9f502b92d7928e3b3fde6d3735"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLIM DOG GROUP SP Z O O" and
            pe.signatures[i].serial == "0d:dc:e8:cd:c9:1b:5b:64:9b:b4:b4:5f:fb:ba:6c:6c"
        )
}

rule INDICATOR_KB_CERT_4af27cd14f5c809eec1f46e483f03898 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5fa9a98f003f2680718cbe3a7a3d57d7ba347ecb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DAhan Advertising planning" and
            pe.signatures[i].serial == "4a:f2:7c:d1:4f:5c:80:9e:ec:1f:46:e4:83:f0:38:98"
        )
}

rule INDICATOR_KB_CERT_105765998695197de4109828a68a4ee0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5ddae14820d6f189e637f90b81c4fdb78b5419dc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cryptonic ApS" and
            pe.signatures[i].serial == "10:57:65:99:86:95:19:7d:e4:10:98:28:a6:8a:4e:e0"
        )
}

rule INDICATOR_KB_CERT_53f575f7c33ee007887f30680486db5e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a42d8f60663dd86265e566f33d0ed5554e4c9a50"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RET PTY. LTD." and
            pe.signatures[i].serial == "53:f5:75:f7:c3:3e:e0:07:88:7f:30:68:04:86:db:5e"
        )
}

rule INDICATOR_KB_CERT_7e89b9df006bd1aa4c48d865039634ca {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "63ad44acaa7cd7f8249423673fbf3c3273e7b2dc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dummy" and
            pe.signatures[i].serial == "7e:89:b9:df:00:6b:d1:aa:4c:48:d8:65:03:96:34:ca"
        )
}

rule INDICATOR_KB_CERT_0ddeb53f957337fbeaf98c4a615b149d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "91cabea509662626e34326687348caf2dd3b4bba"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Mozilla Corporation" and
            pe.signatures[i].serial == "0d:de:b5:3f:95:73:37:fb:ea:f9:8c:4a:61:5b:14:9d"
        )
}

rule INDICATOR_KB_CERT_00c88af896b6452241fe00e3aaec11b1f8 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9ce1cbf5be77265af2a22e28f8930c2ac5641e12"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TeamViewer Germany GmbH" and
            pe.signatures[i].serial == "00:c8:8a:f8:96:b6:45:22:41:fe:00:e3:aa:ec:11:b1:f8"
        )
}

rule INDICATOR_KB_CERT_09e015e98e4fabcc9ac43e042c96090d {
    meta:
        author = "ditekSHen"
        description = "Detects BestEncrypt commercial disk encryption and wiping software signing certificate"
        thumbprint = "04e407118516053ff248503b31d6eec6daf4a809"
        reference1 = "https://www.virustotal.com/gui/file/859f845ee7c741f34ce8bd53d0fe806eccc2395fc413077605fae3db822094b4/details"
        reference2 = "https://blog.macnica.net/blog/2020/11/dtrack.html"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jetico Inc. Oy" and
            pe.signatures[i].serial == "09:e0:15:e9:8e:4f:ab:cc:9a:c4:3e:04:2c:96:09:0d"
        )
}

rule INDICATOR_KB_CERT_118d813d830f218c0f46d4fc {
    meta:
        author = "ditekSHen"
        description = "Detects BestEncrypt commercial disk encryption and wiping software signing certificate"
        thumbprint = "bd16f70bf6c2ef330c5a4f3a27856a0d030d77fa"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shang Hai Shen Wei Wang Luo Ke Ji You Xian Gong Si" and
            pe.signatures[i].serial == "11:8d:81:3d:83:0f:21:8c:0f:46:d4:fc"
        )
}

rule INDICATOR_KB_CERT_2304ecf0ea2b2736beddd26a903ba952 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d59a63e230cef77951cb73a8d65576f00c049f44"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\x88\\x90\\xE9\\x83\\xBD\\xE5\\x90\\x89\\xE8\\x83\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE8\\xB4\\xA3\\xE4\\xBB\\xBB\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "23:04:ec:f0:ea:2b:27:36:be:dd:d2:6a:90:3b:a9:52"
        )
}

rule INDICATOR_KB_CERT_4d78e90e0950fc630000000055657e1a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "fd010fdee2314f5d87045d1d7bf0da01b984b0fe"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Telus Health Solutions Inc." and
            pe.signatures[i].serial == "4d:78:e9:0e:09:50:fc:63:00:00:00:00:55:65:7e:1a"
        )
}

rule INDICATOR_KB_CERT_0092bc051f1811bb0b86727c36394f7849 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d1f9930521e172526a9f018471d4575d60d8ad8f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MISTO EKONOMSKE STORITVE, d.o.o." and
            pe.signatures[i].serial == "00:92:bc:05:1f:18:11:bb:0b:86:72:7c:36:39:4f:78:49"
        )
}

rule INDICATOR_KB_CERT_b4f42e2c153c904fda64c957ed7e1028 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ed4c50ab4f173cf46386a73226fa4dac9cadc1c4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NONO spol. s r.o." and
            pe.signatures[i].serial == "b4:f4:2e:2c:15:3c:90:4f:da:64:c9:57:ed:7e:10:28"
        )
}

rule INDICATOR_KB_CERT_00ac307e5257bb814b818d3633b630326f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4d6a089ec4edcac438717c1d64a8be4ef925a9c6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aqua Direct s.r.o." and
            pe.signatures[i].serial == "00:ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f"
        )
}

rule INDICATOR_KB_CERT_063a7d09107eddd8aa1f733634c6591b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a03f9b3f3eb30ac511463b24f2e59e89ee4c6d4a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Smart Line Logistics" and
            pe.signatures[i].serial == "06:3a:7d:09:10:7e:dd:d8:aa:1f:73:36:34:c6:59:1b"
        )
}

rule INDICATOR_KB_CERT_4c687a0022c36f89e253f91d1f6954e2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4412007ae212d12cea36ed56985bd762bd9fb54a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HETCO ApS" and
            pe.signatures[i].serial == "4c:68:7a:00:22:c3:6f:89:e2:53:f9:1d:1f:69:54:e2"
        )
}

rule INDICATOR_KB_CERT_3cee26c125b8c188f316c3fa78d9c2f1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9efcf68a289d9186ec17e334205cb644c2b6a147"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bitubit LLC" and
            pe.signatures[i].serial == "3c:ee:26:c1:25:b8:c1:88:f3:16:c3:fa:78:d9:c2:f1"
        )
}

rule INDICATOR_KB_CERT_a0a27aefd067ac62ce0247b72bf33de3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "42c2842fa674fdca14c9786aaec0c3078a4f1755"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cfbcdabfdbdccaaccadfeaacacf" and
            pe.signatures[i].serial == "a0:a2:7a:ef:d0:67:ac:62:ce:02:47:b7:2b:f3:3d:e3"
        )
}

rule INDICATOR_KB_CERT_eee8cf0a0e4c78faa03d07470161a90e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "32eda5261359e76a4e66da1ba82db7b7a48295d2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aafabffdbdbcbfcaebdf" and
            pe.signatures[i].serial == "ee:e8:cf:0a:0e:4c:78:fa:a0:3d:07:47:01:61:a9:0e"
        )
}

rule INDICATOR_KB_CERT_79e1cc0f6722e1a2c4647c21023ca4ee {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "41d2f4f810a6edf42b3717cf01d4975476f63cba"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SPAGETTI LTD" and
            pe.signatures[i].serial == "79:e1:cc:0f:67:22:e1:a2:c4:64:7c:21:02:3c:a4:ee"
        )
}

rule INDICATOR_KB_CERT_6d688ecf46286fe4b6823b91384eca86 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "970205140b48d684d0dc737c0fe127460ccfac4f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AtomPark Software JSC" and
            pe.signatures[i].serial == "6d:68:8e:cf:46:28:6f:e4:b6:82:3b:91:38:4e:ca:86"
        )
}

rule INDICATOR_KB_CERT_9aa99f1b75a463460d38c4539fae4f73 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b2ea9e771631f95a927c29b044284ef4f84a2069"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beaacdfaeeccbbedadcb" and
            pe.signatures[i].serial == "9a:a9:9f:1b:75:a4:63:46:0d:38:c4:53:9f:ae:4f:73"
        )
}

rule INDICATOR_KB_CERT_e414655f025399cca4d7225d89689a04 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "98643cef3dc22d0cc730be710c5a30ae25d226c1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\xAF\\x94\\xE5\\x90\\xBE\\xE8\\xBF\\xAA\\xE5\\x90\\xBE\\xE8\\xBF\\xAA\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE8\\xBF\\xAA\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE6\\x8F\\x90\\xE4\\xBC\\x8A\\xE6\\xAF\\x94\\xE6\\x8F\\x90\\xE8\\xBF\\xAA\\xE8\\xBF\\xAA\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE6\\x8F\\x90\\xE7\\xBB\\xB4\\xE6\\xAF\\x94" and
            pe.signatures[i].serial == "e4:14:65:5f:02:53:99:cc:a4:d7:22:5d:89:68:9a:04"
        )
}

rule INDICATOR_KB_CERT_64f82ed8a90f92a940be2bb90fbf6f48 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4d00f5112caf80615852ffe1f4ee72277ed781c3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Klimate Vision Plus" and
            pe.signatures[i].serial == "64:f8:2e:d8:a9:0f:92:a9:40:be:2b:b9:0f:bf:6f:48"
        )
}

rule INDICATOR_KB_CERT_00f0031491b673ecdf533d4ebe4b54697f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "01e201cce1024237978baccf5b124261aa5edb01"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eebbffbceacddbfaeefaecdbaf" and
            pe.signatures[i].serial == "00:f0:03:14:91:b6:73:ec:df:53:3d:4e:be:4b:54:69:7f"
        )
}

rule INDICATOR_KB_CERT_becd4ef55ced54e5bcde595d872ae7eb {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "72ae9b9a32b4c16b5a94e2b4587bc51a91b27052"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dedbfdefcac" and
            pe.signatures[i].serial == "be:cd:4e:f5:5c:ed:54:e5:bc:de:59:5d:87:2a:e7:eb"
        )
}

rule INDICATOR_KB_CERT_55b5e1cf84a89c4e023399784b42a268 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "940345ed6266b67a768296ad49e51bbaa6ee8e97"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fbbdefaccbbcdc" and
            pe.signatures[i].serial == "55:b5:e1:cf:84:a8:9c:4e:02:33:99:78:4b:42:a2:68"
        )
}

rule INDICATOR_KB_CERT_84c3a47b739f1835d35b755d1e6741b5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8057f20f9f385858416ec3c0bd77394eff595b69"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bddbdcfabededdeadbefed" and
            pe.signatures[i].serial == "84:c3:a4:7b:73:9f:18:35:d3:5b:75:5d:1e:67:41:b5"
        )
}

rule INDICATOR_KB_CERT_28f6ca1f249cfb6bdb16bc57aaf0bd79 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0811c227816282094d5212d3c9116593f70077ab"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cdcafaabbdcaaaeaaee" and
            pe.signatures[i].serial == "28:f6:ca:1f:24:9c:fb:6b:db:16:bc:57:aa:f0:bd:79"
        )
}

rule INDICATOR_KB_CERT_2c3e87b9d430c2f0b14fc1152e961f1a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "80daa4ad14fc420d7708f2855e6fab085ca71980"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Abfaacccde" and
            pe.signatures[i].serial == "2c:3e:87:b9:d4:30:c2:f0:b1:4f:c1:15:2e:96:1f:1a"
        )
}

rule INDICATOR_KB_CERT_4808c88ea243eefa47610d5f5f0d02a2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5dc400de1133be3ff17ff09f8a1fd224b3615e5a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bfcdcdfcdfcaaeff" and
            pe.signatures[i].serial == "48:08:c8:8e:a2:43:ee:fa:47:61:0d:5f:5f:0d:02:a2"
        )
}

rule INDICATOR_KB_CERT_2f184a6f054dc9f7c74a63714b14ce33 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed AprelTech Silent Install Builder certificate"
        thumbprint = "ec9c6a537f6d7a0e63a4eb6aeb0df9d5b466cc58"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APREL Tehnologija d.o.o." and
            pe.signatures[i].serial == "2f:18:4a:6f:05:4d:c9:f7:c7:4a:63:71:4b:14:ce:33"
        )
}

rule INDICATOR_KB_CERT_00ced72cc75aa0ebce09dc0283076ce9b1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "db77b48a7f16fecd49029b65f122fa0782b4318f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Valerie LLC" and
            pe.signatures[i].serial == "00:ce:d7:2c:c7:5a:a0:eb:ce:09:dc:02:83:07:6c:e9:b1"
        )
}

rule INDICATOR_KB_CERT_c4564802095258281a284809930dcf43 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "73db2555f20b171ce9502eb6507add9fa53a5bf3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cfeaaeedaefddfaaccefcdbae" and
            pe.signatures[i].serial == "c4:56:48:02:09:52:58:28:1a:28:48:09:93:0d:cf:43"
        )
}

rule INDICATOR_KB_CERT_3d31ed3b22867f425db86fb532eb449f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1e708efa130d1e361afb76cc94ba22aca3553590"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Badfcbdbcdbfafcaeebad" and
            pe.signatures[i].serial == "3d:31:ed:3b:22:86:7f:42:5d:b8:6f:b5:32:eb:44:9f"
        )
}

rule INDICATOR_KB_CERT_531549ed4d2d53fc7e1beb47c6b13d58 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a8e1f6e32e5342265dd3e28cc65060fb7221c529"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bdabfbdfbcbab" and
            pe.signatures[i].serial == "53:15:49:ed:4d:2d:53:fc:7e:1b:eb:47:c6:b1:3d:58"
        )
}

rule INDICATOR_KB_CERT_8035ed9c58ea895505b05ff926d486bc {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b82a7f87b7d7ccea50bba5fe8d8c1c745ebcb916"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fecddacdddfaadcddcabceded" and
            pe.signatures[i].serial == "80:35:ed:9c:58:ea:89:55:05:b0:5f:f9:26:d4:86:bc"
        )
}

rule INDICATOR_KB_CERT_ca646b4275406df639cf603756f63d77 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2a68cfad2d82caae48d4dcbb49aa73aaf3fe79dd"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SHOECORP LIMITED" and
            (
                pe.signatures[i].serial == "ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77" or
                pe.signatures[i].serial == "00:ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77"
            )
        )
}

rule INDICATOR_KB_CERT_00e267fdbdc16f22e8185d35c437f84c87 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "cdf4a69402936ece82f3f9163e6cc648bcbb2680"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APOTHEKA, s.r.o." and
            pe.signatures[i].serial == "00:e2:67:fd:bd:c1:6f:22:e8:18:5d:35:c4:37:f8:4c:87"
        )
}

rule INDICATOR_KB_CERT_00taffias {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "88d563dccb2ffc9c5f6d6a3721ad17203768735a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TAFFIAS" and
            pe.signatures[i].serial == "00"
        )
}

rule INDICATOR_KB_CERT_9f2492304fc9c93844dea7e5d6f0ec77 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "33015f23712f36e3ec310cfd1b16649abb645a98"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bbddebeea" and
            pe.signatures[i].serial == "9f:24:92:30:4f:c9:c9:38:44:de:a7:e5:d6:f0:ec:77"
        )
}

rule INDICATOR_KB_CERT_dca9012634e8b609884fe9284d30eff5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "60971c18c7efb4a294f1d8ee802ff3d581c77834"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bebaeefaeba" and (
                pe.signatures[i].serial == "dc:a9:01:26:34:e8:b6:09:88:4f:e9:28:4d:30:ef:f5" or
                pe.signatures[i].serial == "00:dc:a9:01:26:34:e8:b6:09:88:4f:e9:28:4d:30:ef:f5"    
            )
        )
}

rule INDICATOR_KB_CERT_781ec65c3e38392d4c2f9e7f55f5c424 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5d20e8f899c7e48a0269c2b504607632ba833e40"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Facacafbfddbdbfad" and
            pe.signatures[i].serial == "78:1e:c6:5c:3e:38:39:2d:4c:2f:9e:7f:55:f5:c4:24"
        )
}

rule INDICATOR_KB_CERT_bd1e93d5787a737eef930c70986d2a69 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "921e5d7f9f05272b566533393d7194ea9227e582"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cdefedddbdedbcbfffbeadb" and
            pe.signatures[i].serial == "bd:1e:93:d5:78:7a:73:7e:ef:93:0c:70:98:6d:2a:69"
        )
}

rule INDICATOR_KB_CERT_b0009bb062f52eb6001ba79606de243d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c89f06937d24b7f13be5edba5e0e2f4e05bc9b13"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fbfdddcfabc" and
            pe.signatures[i].serial == "b0:00:9b:b0:62:f5:2e:b6:00:1b:a7:96:06:de:24:3d"
        )
}

rule INDICATOR_KB_CERT_294e7a2ccfc28ed02843ecff25f2ac98 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a57a2de9b04a80e9290df865c0abd3b467318144"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eadbaadbdcecafdfafbe" and
            pe.signatures[i].serial == "29:4e:7a:2c:cf:c2:8e:d0:28:43:ec:ff:25:f2:ac:98"
        )
}

rule INDICATOR_KB_CERT_a61b5590c2d8dc70a31f8ea78cda4353 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d1f77736e8594e026f67950ca2bf422bb12abc3a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bdddcfaebffbfdcabaffe" and
            pe.signatures[i].serial == "a6:1b:55:90:c2:d8:dc:70:a3:1f:8e:a7:8c:da:43:53"
        )
}

rule INDICATOR_KB_CERT_21c9a6daff942f2db6a0614d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7dd9acb2ef0402883c65901ebbafd06e5293d391"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ledger SAS" and
            pe.signatures[i].serial == "21:c9:a6:da:ff:94:2f:2d:b6:a0:61:4d"
        )
}

rule INDICATOR_KB_CERT_1f55ae3fca38827cde6cc7ca1c0d2731 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a279fa4186ef598c5498ba5c0037c7bd4bd57272"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fcceaeafbbdccccddfbbb" and
            pe.signatures[i].serial == "1f:55:ae:3f:ca:38:82:7c:de:6c:c7:ca:1c:0d:27:31"
        )
}

rule INDICATOR_KB_CERT_008d1bae9f7aef1a2bcc0d392f3edf3a36 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5927654acf9c66912ff7b41dab516233d98c9d72"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beaffbebfeebbefbeeb" and
            pe.signatures[i].serial == "00:8d:1b:ae:9f:7a:ef:1a:2b:cc:0d:39:2f:3e:df:3a:36"
        )
}

rule INDICATOR_KB_CERT_239ba103c2943d2dff5e3211d6800d09 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d8ea0533af5c180ce1f4d6bc377b736208b3efbb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bcafaecbecacbca" and
            pe.signatures[i].serial == "23:9b:a1:03:c2:94:3d:2d:ff:5e:32:11:d6:80:0d:09"
        )
}

rule INDICATOR_KB_CERT_205b80a74a5dddedea6b84a1e1c44010 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1a743595dfaa29cd215ec82a6cd29bb434b709cf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Befadbffde" and
            pe.signatures[i].serial == "20:5b:80:a7:4a:5d:dd:ed:ea:6b:84:a1:e1:c4:40:10"
        )
}

rule INDICATOR_KB_CERT_6c8d0cf4d1593ee8dc8d34be71e90251 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d481d73bcf1e45db382d0e345f3badde6735d17d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dbdbecdbdfafdc" and
            pe.signatures[i].serial == "6c:8d:0c:f4:d1:59:3e:e8:dc:8d:34:be:71:e9:02:51"
        )
}

rule INDICATOR_KB_CERT_7d08a74747557d6016aaaf47a679312f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d7fdad88c626b8e6d076f3f414bbae353f444618"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Abfacfbdcd" and
            pe.signatures[i].serial == "7d:08:a7:47:47:55:7d:60:16:aa:af:47:a6:79:31:2f"
        )
}

rule INDICATOR_KB_CERT_2095c6f1eadb65ce02862bd620623b92 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "940a4d4a5aadef70d8c14caac6f11d653e71800f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Febeecad" and
            pe.signatures[i].serial == "20:95:c6:f1:ea:db:65:ce:02:86:2b:d6:20:62:3b:92"
        )
}

rule INDICATOR_KB_CERT_0b1f8cd59e64746beae153ecca21066b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "74b2e146a82f2b71f8eb4b13ebbb6f951757d8c2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Mozilla Corporation" and
            pe.signatures[i].serial == "0b:1f:8c:d5:9e:64:74:6b:ea:e1:53:ec:ca:21:06:6b"
        )
}

rule INDICATOR_KB_CERT_899e32c9bf2b533b9275c39f8f9ff96d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "329af76d7c84a90f2117893adc255115c3c961c7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eecaaffcbfdffaedcfec" and
            pe.signatures[i].serial == "89:9e:32:c9:bf:2b:53:3b:92:75:c3:9f:8f:9f:f9:6d"
        )
}

rule INDICATOR_KB_CERT_0b5759bc22ad2128b8792e8535f9161e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ddfd6a93a8d33f0797d5fdfdb9abf2b66e64350a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ceeacfeacafdcdffabdbbacf" and
            pe.signatures[i].serial == "0b:57:59:bc:22:ad:21:28:b8:79:2e:85:35:f9:16:1e"
        )
}

rule INDICATOR_KB_CERT_630cf0e612f12805ffa00a41d1032d7c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "107af72db66ec4005ed432e4150a0b6f5a9daf2d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dadebfaca" and
            pe.signatures[i].serial == "63:0c:f0:e6:12:f1:28:05:ff:a0:0a:41:d1:03:2d:7c"
        )
}

rule INDICATOR_KB_CERT_603bce30597089d068320fc77e400d06 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4ddda7e006afb108417627f8f22a6fa416e3f264"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fcaddefffedacfc" and
            pe.signatures[i].serial == "60:3b:ce:30:59:70:89:d0:68:32:0f:c7:7e:40:0d:06"
        )
}

rule INDICATOR_KB_CERT_5d5d03edb4ec4e185caa3041824ab75c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f6c9c564badc1bbd8a804c5e20ab1a0eff89d4c0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ffcdcbacfeaedbfbcecccafeb" and
            pe.signatures[i].serial == "5d:5d:03:ed:b4:ec:4e:18:5c:aa:30:41:82:4a:b7:5c"
        )
}

rule INDICATOR_KB_CERT_aec009984fa957f3f48fe3104ca9babc {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9d5b6bc86775395992a25d21d696d05d634a89d1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ceefaccdedbfbbaaaadacdbf" and
            pe.signatures[i].serial == "ae:c0:09:98:4f:a9:57:f3:f4:8f:e3:10:4c:a9:ba:bc"
        )
}

rule INDICATOR_KB_CERT_283518f1940a11caf187646d8063d61d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "aaeb19203b71e26c857613a5a2ba298c79910f5d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eeeeeeba" and
            pe.signatures[i].serial == "28:35:18:f1:94:0a:11:ca:f1:87:64:6d:80:63:d6:1d"
        )
}

rule INDICATOR_KB_CERT_72f3e4707b94d0eef214384de9b36e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e2a5a2823b0a56c88bfcb2788aa4406e084c4c9b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eaaebecedccfd" and
            pe.signatures[i].serial == "72:f3:e4:70:7b:94:d0:ee:f2:14:38:4d:e9:b3:6e"
        )
}

rule INDICATOR_KB_CERT_00d875b3e3f2db6c3eb426e24946066111 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d27211a59dc8a4b3073d116621b6857c3d70ed04"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kubit LLC" and
            pe.signatures[i].serial == "00:d8:75:b3:e3:f2:db:6c:3e:b4:26:e2:49:46:06:61:11"
        )
}

rule INDICATOR_KB_CERT_3990362c34015ce4c23ecc3377fd3c06 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "48444dec9d6839734d8383b110faabe05e697d45"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RZOH ApS" and
            pe.signatures[i].serial == "39:90:36:2c:34:01:5c:e4:c2:3e:cc:33:77:fd:3c:06"
        )
}

rule INDICATOR_KB_CERT_54a6d33f73129e0ef059ccf51be0c35e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8ada307ab3a8983857d122c4cb48bf3b77b49c63"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STAFFORD MEAT COMPANY, INC." and
            pe.signatures[i].serial == "54:a6:d3:3f:73:12:9e:0e:f0:59:cc:f5:1b:e0:c3:5e"
        )
}

rule INDICATOR_KB_CERT_0a55c15f733bf1633e9ffae8a6e3b37d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "591f68885fc805a10996262c93aab498c81f3010"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Osnova OOO" and
            pe.signatures[i].serial == "0a:55:c1:5f:73:3b:f1:63:3e:9f:fa:e8:a6:e3:b3:7d"
        )
}

rule INDICATOR_KB_CERT_00f675139ea68b897a865a98f8e4611f00 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "06d46ee9037080c003983d76be3216b7cad528f8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BS TEHNIK d.o.o." and
            pe.signatures[i].serial == "00:f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00"
        )
}

rule INDICATOR_KB_CERT_121fca3cfa4bd011669f5cc4e053aa3f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "84b5ef4f981020df2385754ab1296821fa2f8977"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kymijoen Projektipalvelut Oy" and
            pe.signatures[i].serial == "12:1f:ca:3c:fa:4b:d0:11:66:9f:5c:c4:e0:53:aa:3f"
        )
}

rule INDICATOR_KB_CERT_62b80fc5e1c02072019c88ee356152c1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0a83c0f116020fc1f43558a9a08b1f8bcbb809e0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Inversum" and
            pe.signatures[i].serial == "62:b8:0f:c5:e1:c0:20:72:01:9c:88:ee:35:61:52:c1"
        )
}

rule INDICATOR_KB_CERT_01803bc7537a1818c4ab135469963c10 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "197839b47cf975c3d6422404cbbbb5bc94f4eb46"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rare Ideas LLC" and
            pe.signatures[i].serial == "01:80:3b:c7:53:7a:18:18:c4:ab:13:54:69:96:3c:10"
        )
}

rule INDICATOR_KB_CERT_f0e150c304de35f2e9086185581f4053 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c0a448b9101f48309a8e5a67c11db09da14b54bb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rare Ideas, LLC" and
            pe.signatures[i].serial == "f0:e1:50:c3:04:de:35:f2:e9:08:61:85:58:1f:40:53"
        )
}

rule INDICATOR_KB_CERT_a1a3e7280e0a2df12f84309649820519 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "33d254c711937b469d1b08ef15b0a9f5b4d27250"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nir Sofer" and
            pe.signatures[i].serial == "a1:a3:e7:28:0e:0a:2d:f1:2f:84:30:96:49:82:05:19"
        )
}

rule INDICATOR_KB_CERT_1fb984d5a7296ba74445c23ead7d20aa {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c852fc9670391ff077eb2590639051efa42db5c9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DrWeb Digital LLC" and
            pe.signatures[i].serial == "1f:b9:84:d5:a7:29:6b:a7:44:45:c2:3e:ad:7d:20:aa"
        )
}

rule INDICATOR_KB_CERT_c314a8736f82c411b9f02076a6db4771 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9c49d7504551ad4ddffad206b095517a386e8a14"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cbcbaeaabbfcebfcbbeeffeadfc" and
            pe.signatures[i].serial == "c3:14:a8:73:6f:82:c4:11:b9:f0:20:76:a6:db:47:71"
        )
}

rule INDICATOR_KB_CERT_5f7ef778d51cd33a5fc0d2e035ccd29d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "87229a298b8de0c7b8d4e23119af1e7850a073f5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ffadbcfabbe" and
            pe.signatures[i].serial == "5f:7e:f7:78:d5:1c:d3:3a:5f:c0:d2:e0:35:cc:d2:9d"
        )
}

rule INDICATOR_KB_CERT_00ab1d5e43e4dde77221381e21a764c082 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b84a817517ed50dbae5439be54248d30bd7a3290"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dadddbffbfcbdaaeeccecbbffac" and
            pe.signatures[i].serial == "00:ab:1d:5e:43:e4:dd:e7:72:21:38:1e:21:a7:64:c0:82"
        )
}

rule INDICATOR_KB_CERT_4743e140c05b33f0449023946bd05acb {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7b32c8cc35b86608c522a38c4fe38ebaa57f27675504cba32e0ab6babbf5094a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STROI RENOV SARL" and
            pe.signatures[i].serial == "47:43:e1:40:c0:5b:33:f0:44:90:23:94:6b:d0:5a:cb"
        )
}

rule INDICATOR_KB_CERT_2c1ee9b583310b5e34a1ee6945a34b26 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7af96a09b6c43426369126cfffac018f11e5562cb64d32e5140cff3f138ffea4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Artmarket" and
            pe.signatures[i].serial == "2c:1e:e9:b5:83:31:0b:5e:34:a1:ee:69:45:a3:4b:26"
        )
}

rule INDICATOR_KB_CERT_00d338f8a490e37e6c2be80a0e349929fa {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "480a9ce15fc76e03f096fda5af16e44e0d6a212d6f09a898f51ad5206149bbe1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SAGUARO ApS" and
            pe.signatures[i].serial == "00:d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa"
        )
}

rule INDICATOR_KB_CERT_778906d40695f65ba518db760df44cd3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1103debcb1e48f7dda9cec4211c0a7a9c1764252"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            //pe.signatures[i].subject contains "\\xD0\\x9E\\xD0\\x9E\\xD0\\x9E \"\\xD0\\x98\\xD0\\x9D\\xD0\\xA2\\xD0\\x95\\xD0\\x9B\\xD0\\x9B\\xD0\\x98\\xD0\\xA2\"" and
            pe.signatures[i].serial == "77:89:06:d4:06:95:f6:5b:a5:18:db:76:0d:f4:4c:d3"
        )
}

rule INDICATOR_KB_CERT_45eb9187a2505d8e6c842e6d366ad0c8 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "63938d34572837514929fa7ae3cfebedf6d2cb65"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BAKERA s.r.o." and
            pe.signatures[i].serial == "45:eb:91:87:a2:50:5d:8e:6c:84:2e:6d:36:6a:d0:c8"
        )
}

rule INDICATOR_KB_CERT_cbc2af7d82295a8535f3b26b47522640 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "08d2c03d0959905b4b04caee1202b8ed748a8bd0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eabfdafffefaccaedaec" and
            pe.signatures[i].serial == "cb:c2:af:7d:82:29:5a:85:35:f3:b2:6b:47:52:26:40"
        )
}

rule INDICATOR_KB_CERT_0ca1d9391cf5fe3e696831d98d6c35a6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0689776ca5ca0ca9641329dc29efdb61302d7378"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "www.norton.com" and
            pe.signatures[i].serial == "0c:a1:d9:39:1c:f5:fe:3e:69:68:31:d9:8d:6c:35:a6"
        )
}

rule INDICATOR_KB_CERT_43a36a26ebc78e111a874d8211a95e3f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a346bda33b5b3bea04b299fe87c165c4f221645a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Efacefcafeabbdcbcea" and
            pe.signatures[i].serial == "43:a3:6a:26:eb:c7:8e:11:1a:87:4d:82:11:a9:5e:3f"
        )
}

rule INDICATOR_KB_CERT_5172caa2119185382343fcbe09c43bee {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "fd9b3f6b0eb9bd9baf7cbdc79ae7979b7ddad770"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aefcdac" and
            pe.signatures[i].serial == "51:72:ca:a2:11:91:85:38:23:43:fc:be:09:c4:3b:ee"
        )
}

rule INDICATOR_KB_CERT_009245d1511923f541844faa3c6bfebcbe {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "509cbd2cd38ae03461745c7d37f6bbe44c6782cf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LEHTEH d.o.o.," and
            pe.signatures[i].serial == "00:92:45:d1:51:19:23:f5:41:84:4f:aa:3c:6b:fe:bc:be"
        )
}

rule INDICATOR_KB_CERT_00e161f76da3b5e4623892c8e6fda1ea3d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "df5fbfbfd47875b580b150603de240ead9c7ad27"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TGN Nedelica d.o.o." and
            pe.signatures[i].serial == "00:e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d"
        )
}

rule INDICATOR_KB_CERT_009faf8705a3eaef9340800cc4fd38597c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "40c572cc19e7ca4c2fb89c96357eff4c7489958e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tekhnokod LLC" and
            pe.signatures[i].serial == "00:9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c"
        )
}

rule INDICATOR_KB_CERT_2888cf0f953a4a3640ee4cfc6304d9d4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "eb5f5ab7294ba39f2b77085f47382bd7e759ff3a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lotte Schmidt" and
            pe.signatures[i].serial == "28:88:cf:0f:95:3a:4a:36:40:ee:4c:fc:63:04:d9:d4"
        )
}

rule INDICATOR_KB_CERT_00c8edcfe8be174c2f204d858c5b91dea5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7f5f205094940793d1028960e0f0e8b654f9956e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Paarcopy Oy" and
            pe.signatures[i].serial == "00:c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5"
        )
}

rule INDICATOR_KB_CERT_1a311630876f694fe1b75d972a953bca {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d473ec0fe212b7847f1a4ee06eff64e2a3b4001e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GTEC s.r.o." and
            pe.signatures[i].serial == "1a:31:16:30:87:6f:69:4f:e1:b7:5d:97:2a:95:3b:ca"
        )
}

rule INDICATOR_KB_CERT_00a496bc774575c31abec861b68c36dcb6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b2c70d30c0b34bfeffb8a9cb343e5cad5f6bcbf7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ORGLE DVORSAK, d.o.o" and
            pe.signatures[i].serial == "00:a4:96:bc:77:45:75:c3:1a:be:c8:61:b6:8c:36:dc:b6"
        )
}

rule INDICATOR_KB_CERT_00ea720222d92dc8d48e3b3c3b0fc360a6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "522d0f1ca87ef784994dfd63cb0919722dfdb79f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CAVANAGH NETS LIMITED" and
            pe.signatures[i].serial == "00:ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6"
        )
}

rule INDICATOR_KB_CERT_333ca7d100b139b0d9c1a97cb458e226 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d618cf7ef3a674ff1ea50800b4d965de0ff463cb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FSE, d.o.o." and
            pe.signatures[i].serial == "33:3c:a7:d1:00:b1:39:b0:d9:c1:a9:7c:b4:58:e2:26"
        )
}

rule INDICATOR_KB_CERT_58ec8821aa2a3755e1075f73321756f4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "19dd0d7f2edf32ea285577e00dd13c966844cfa4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cbebbfeaddcbcccffdcdc" and
            pe.signatures[i].serial == "58:ec:88:21:aa:2a:37:55:e1:07:5f:73:32:17:56:f4"
        )
}

rule INDICATOR_KB_CERT_0940fa9a4080f35052b2077333769c2f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "da154c058cd75ff478b248701799ea8c683dd7a5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PROFF LAIN, OOO" and
            pe.signatures[i].serial == "09:40:fa:9a:40:80:f3:50:52:b2:07:73:33:76:9c:2f"
        )
}

rule INDICATOR_KB_CERT_56fff139df5ae7e788e5d72196dd563a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0f69ccb73a6b98f548d00f0b740b6e42907efaad"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cifromatika LLC" and
            pe.signatures[i].serial == "56:ff:f1:39:df:5a:e7:e7:88:e5:d7:21:96:dd:56:3a"
        )
}

rule INDICATOR_KB_CERT_03d433fdc2469e9fd878c80bc0545147 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "64e90267e6359060a8669aebb94911e92bd0c5f3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xEC\\xA3\\xBC\\xEC\\x8B\\x9D\\xED\\x9A\\x8C\\xEC\\x82\\xAC \\xEC\\x97\\x98\\xEB\\xA6\\xAC\\xEC\\x8B\\x9C\\xEC\\x98\\xA8\\xEB\\x9E\\xA9" and
            pe.signatures[i].serial == "03:d4:33:fd:c2:46:9e:9f:d8:78:c8:0b:c0:54:51:47"
        )
}

rule INDICATOR_KB_CERT_0be3f393d1ef0272aed0e2319c1b5dd0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7745253a3f65311b84d8f64b74f249364d29e765"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Invincea, Inc." and
            pe.signatures[i].serial == "0b:e3:f3:93:d1:ef:02:72:ae:d0:e2:31:9c:1b:5d:d0"
        )
}

rule INDICATOR_KB_CERT_65628c146ace93037fc58659f14bd35f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b59165451be46b8d72d09191d0961c755d0107c8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ESET, spol. s r.o." and
            pe.signatures[i].serial == "65:62:8c:14:6a:ce:93:03:7f:c5:86:59:f1:4b:d3:5f"
        )
}

rule INDICATOR_KB_CERT_0084817e07288a5025b9435570e7fec1d3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f22e8c59b7769e4a9ade54aee8aaf8404a7feaa7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE8\\xB4\\xBC\\xE8\\x89\\xBE\\xE5\\xBE\\xB7\\xE8\\xB4\\xBC\\xE6\\x8F\\x90\\xD0\\xAD\\xD0\\xAD\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE8\\xB4\\xBC\\xD0\\xAD\\xE5\\xBE\\xB7\\xE8\\xB4\\xBC\\xE8\\xB4\\xBC\\xE5\\xB0\\x94\\xE6\\x8F\\x90\\xE8\\x89\\xBE\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE5\\xB0\\x94\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE8\\x89\\xBE\\xD0\\xAD\\xE8\\x89\\xBE" and
            pe.signatures[i].serial == "00:84:81:7e:07:28:8a:50:25:b9:43:55:70:e7:fe:c1:d3"
        )
}

rule INDICATOR_KB_CERT_4d26bab89fcf7ff9fa4dc4847e563563 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2be34a7a39df38f66d5550dcfa01850c8f165c81"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "qvarn pty ltd" and
            pe.signatures[i].serial == "4d:26:ba:b8:9f:cf:7f:f9:fa:4d:c4:84:7e:56:35:63"
        )
}

rule INDICATOR_KB_CERT_00d9d419c9095a79b1f764297addb935da {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7d45ec21c0d6fd0eb84e4271655eb0e005949614"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Nova soft" and
            pe.signatures[i].serial == "00:d9:d4:19:c9:09:5a:79:b1:f7:64:29:7a:dd:b9:35:da"
        )
}

rule INDICATOR_KB_CERT_02e44d7d1d38ae223b27a02bacd79b53 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "34e0ecae125302d5b1c4a7412dbf17bdc1b59f04"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Zhuhai Kingsoft Office Software Co., Ltd." and
            pe.signatures[i].serial == "02:e4:4d:7d:1d:38:ae:22:3b:27:a0:2b:ac:d7:9b:53"
        )
}

rule INDICATOR_KB_CERT_041868dd49840ff44f8e3d3070568350 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e104f236e3ee7d21a0ea8053fe8fc5c412784079"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Zhuhai Kingsoft Office Software Co., Ltd." and
            pe.signatures[i].serial == "04:18:68:dd:49:84:0f:f4:4f:8e:3d:30:70:56:83:50"
        )
}

rule INDICATOR_KB_CERT_c501b7176b29a3cb737361cf85414874 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0788801185a6bf70b805c2b97a7c6ce66cfbb38d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x8B\\x92\\xE8\\x89\\xBE\\xE8\\xAF\\xB6\\xE8\\x89\\xBE\\xE8\\xB4\\x9D\\xE8\\xAF\\xB6\\xE8\\xAF\\xB6\\xE8\\xB4\\x9D\\xE5\\x90\\xBE\\xE5\\xBC\\x97\\xE5\\xBC\\x97\\xE5\\x90\\xBE\\xE8\\xAF\\xB6\\xE5\\x8B\\x92\\xE8\\xB4\\x9D\\xE5\\xBC\\x97\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE8\\xAF\\xB6\\xE8\\x89\\xBE\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE8\\x89\\xBE\\xE5\\xBC\\x97\\xE5\\xBC\\x97" and
            pe.signatures[i].serial == "c5:01:b7:17:6b:29:a3:cb:73:73:61:cf:85:41:48:74"
        )
}

rule INDICATOR_KB_CERT_234bf4ef892df307373638014b35ab37 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "348f7e395c77e29c1e17ef9d9bd24481657c7ae7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            //pe.signatures[i].subject contains "\\xD0\\x9E\\xD0\\x9E\\xD0\\x9E \"\\xD0\\xA1\\xD0\\x9A\\xD0\\x90\\xD0\\xA0\\xD0\\x90\\xD0\\x91\\xD0\\x95\\xD0\\x99\"" and
            pe.signatures[i].serial == "23:4b:f4:ef:89:2d:f3:07:37:36:38:01:4b:35:ab:37"
        )
}

rule INDICATOR_KB_CERT_c650ae531100a91389a7f030228b3095 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "05eebfec568abc5fc4b2fd9e5eca087b02e49f53"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "POKEROWA STRUNA SP Z O O" and
            pe.signatures[i].serial == "c6:50:ae:53:11:00:a9:13:89:a7:f0:30:22:8b:30:95"
        )
}

rule INDICATOR_KB_CERT_4f8ebbb263f3cbe558d37118c43f8d58 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3f27a35fe7af06977138d02ad83ddbf13a67b7c3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Maxthon Technology Co, Ltd." and
            pe.signatures[i].serial == "4f:8e:bb:b2:63:f3:cb:e5:58:d3:71:18:c4:3f:8d:58"
        )
}

rule INDICATOR_KB_CERT_01ea62e443cb2250c870ff6bb13ba98e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f293eed3ff3d548262cddc43dce58cfc7f763622"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tencent Technology(Shenzhen) Company Limited" and
            pe.signatures[i].serial == "01:ea:62:e4:43:cb:22:50:c8:70:ff:6b:b1:3b:a9:8e"
        )
}

rule INDICATOR_KB_CERT_726ee7f5999b9e8574ec59969c04955c {
    meta:
        author = "ditekSHen"
        description = "Detects IntelliAdmin commercial remote administration signing certificate"
        thumbprint = "2fb952bc1e3fcf85f68d6e2cb5fc46a519ce3fa9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IntelliAdmin, LLC" and
            pe.signatures[i].serial == "72:6e:e7:f5:99:9b:9e:85:74:ec:59:96:9c:04:95:5c"
        )
}

rule INDICATOR_KB_CERT_0a005d2e2bcd4137168217d8c727747c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "df788aa00eb400b552923518108eb1d4f5b7176b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing JoinHope Image Technology Ltd." and
            pe.signatures[i].serial == "0a:00:5d:2e:2b:cd:41:37:16:82:17:d8:c7:27:74:7c"
        )
}

rule INDICATOR_KB_CERT_00d3d74ae548830d5b1bca9856e16c564a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3f996b75900d566bc178f36b3f4968e2a08365e8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Insite Software Inc." and
            pe.signatures[i].serial == "00:d3:d7:4a:e5:48:83:0d:5b:1b:ca:98:56:e1:6c:56:4a"
        )
}

rule INDICATOR_KB_CERT_41f8253e1ceafbfd8e49f32c34a68f9e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "02e739740b88328ac9c4a6de0ee703b7610f977b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shenzhen Smartspace Software technology Co.,Limited" and
            pe.signatures[i].serial == "41:f8:25:3e:1c:ea:fb:fd:8e:49:f3:2c:34:a6:8f:9e"
        )
}

rule INDICATOR_KB_CERT_0a5b4f67ad8b22afc2debe6ce5f8f679 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1213865af7ddac1568830748dbdda21498dfb0ba"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Farad LLC" and
            pe.signatures[i].serial == "0a:5b:4f:67:ad:8b:22:af:c2:de:be:6c:e5:f8:f6:79"
        )
}

rule INDICATOR_KB_CERT_65cd323c2483668b90a44a711d2a6b98 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "188810cf106a5f38fe8aa0d494cbd027da9edf97"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Giperion" and
            pe.signatures[i].serial == "65:cd:32:3c:24:83:66:8b:90:a4:4a:71:1d:2a:6b:98"
        )
}

rule INDICATOR_KB_CERT_0d07705fa0e0c4827cc287cfcdec20c4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ba5f8c3d961d0df838361b4aa5ec600a70abe1e0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Binance Holdings Limited" and
            pe.signatures[i].serial == "0d:07:70:5f:a0:e0:c4:82:7c:c2:87:cf:cd:ec:20:c4"
        )
}

rule INDICATOR_KB_CERT_0f7e3fda780e47e171864d8f5386bc05 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1e3dd5576fc57fa2dd778221a60bd33f97087f74"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Louhos Solutions Oy" and
            pe.signatures[i].serial == "0f:7e:3f:da:78:0e:47:e1:71:86:4d:8f:53:86:bc:05"
        )
}

rule INDICATOR_KB_CERT_0f9d91c6aba86f4e54cbb9ef57e68346 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3c92c9274ab6d3dd520b13029a2490c4a1d98bc0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kaspersky Lab" and
            pe.signatures[i].serial == "0f:9d:91:c6:ab:a8:6f:4e:54:cb:b9:ef:57:e6:83:46"
        )
}

rule INDICATOR_KB_CERT_07f9d80b85ceff7ee3f58dc594fe66b6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "bf9254919794c1075ea027889c5d304f1121c653"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kaspersky Lab" and
            pe.signatures[i].serial == "07:f9:d8:0b:85:ce:ff:7e:e3:f5:8d:c5:94:fe:66:b6"
        )
}

rule INDICATOR_KB_CERT_c2cbbd946bc3fdb944d522931d61d51a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with Sordum Software certificate, particularly Defender Control"
        thumbprint = "f5e71628a478a248353bf0177395223d2c5a0e43"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sordum Software" and
            pe.signatures[i].serial == "c2:cb:bd:94:6b:c3:fd:b9:44:d5:22:93:1d:61:d5:1a"
        )
}

rule INDICATOR_KB_CERT_6e3b09f43c3a0fd53b7d600f08fae2b5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "677054afcbfecb313f93f27ed159055dc1559ad0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Divisible Limited" and
            pe.signatures[i].serial == "6e:3b:09:f4:3c:3a:0f:d5:3b:7d:60:0f:08:fa:e2:b5"
        )
}

rule INDICATOR_KB_CERT_00aa12c95d2bcde0ce141c6f1145b0d7ef {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1383c4aa2900882f9892696c537e83f1fb20a43f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PROKON, OOO" and
            pe.signatures[i].serial == "00:aa:12:c9:5d:2b:cd:e0:ce:14:1c:6f:11:45:b0:d7:ef"
        )
}

rule INDICATOR_KB_CERT_03e9eb4dff67d4f9a554a422d5ed86f3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8f2de7e770a8b1e412c2de131064d7a52da62287"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "philandro Software GmbH" and
            pe.signatures[i].serial == "03:e9:eb:4d:ff:67:d4:f9:a5:54:a4:22:d5:ed:86:f3"
        )
}

rule INDICATOR_KB_CERT_4a7f07c5d4ad2e23f9e8e03f0e229dd4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b37e7f9040c4adc6d29da6829c7a35a2f6a56fdb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Danalis LLC" and
            pe.signatures[i].serial == "4a:7f:07:c5:d4:ad:2e:23:f9:e8:e0:3f:0e:22:9d:d4"
        )
}

rule INDICATOR_KB_CERT_c6d7ad852af211bf48f19cc0242dcd72 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "bddcef09f222ea4270d4a1811c10f4fcf98e4125"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APDZQKILIIQVIJSCTY" and
            pe.signatures[i].serial == "c6:d7:ad:85:2a:f2:11:bf:48:f1:9c:c0:24:2d:cd:72"
        )
}

rule INDICATOR_KB_CERT_0084888d5a12228e8950683ecdab62fe7a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "390b23ed9750745e8441e35366b294a2a5c66fcd"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ub30 Limited" and
            pe.signatures[i].serial == "00:84:88:8d:5a:12:22:8e:89:50:68:3e:cd:ab:62:fe:7a"
        )
}

rule INDICATOR_KB_CERT_709d547a2f09d39c4c2334983f2cbf50 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f10095c5e36e6bce0759f52dd11137756adc3b53"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BMUZVYUGWSQWLAIISX" and
            pe.signatures[i].serial == "70:9d:54:7a:2f:09:d3:9c:4c:23:34:98:3f:2c:bf:50"
        )
}

rule INDICATOR_KB_CERT_98a04ea05e8a949a4d880d0136794df3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0387ce856978cfa3e161fc03751820f003b478f3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FRVFMPRLNIMAMSUIMT" and
            pe.signatures[i].serial == "98:a0:4e:a0:5e:8a:94:9a:4d:88:0d:01:36:79:4d:f3"
        )
}

rule INDICATOR_KB_CERT_2355895f1759e9e3648026f4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f46d457898d436769f0c70127044e2019583ee16"
        hash1 = "f4f4a5953d0c87db611fa05bb51672591295049978a0e9e14eca8224254ecd7a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Avira Operations GmbH & Co. KG" and
            pe.signatures[i].serial == "23:55:89:5f:17:59:e9:e3:64:80:26:f4"
        )
}

rule INDICATOR_KB_CERT_04f131322cc31d92c849fca351d2f141 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1e6706b746a7409f4e9a39855c5dde4155a13056"
        hash1 = "a19177caff09dfa62c5a5598221cefd7e8871e81bda0cdc9f09c98180360a1e3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Discord Inc." and
            pe.signatures[i].serial == "04:f1:31:32:2c:c3:1d:92:c8:49:fc:a3:51:d2:f1:41"
        )
}

rule INDICATOR_KB_CERT_00818631110b5d14331dac7e6ad998b902 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c93082334ef8c2d6a0a1823cdf632c0d75d56377"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "2 TOY GUYS LLC" and
            (
                pe.signatures[i].serial == "00:81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02" or
                pe.signatures[i].serial == "81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02"
            )
        )
}

rule INDICATOR_KB_CERT_7ab21306b11ff280a93fc445876988ab {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6d0d10933b355ee2d8701510f22aff4a06adbe5b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABC BIOS d.o.o." and
            pe.signatures[i].serial == "7a:b2:13:06:b1:1f:f2:80:a9:3f:c4:45:87:69:88:ab"
        )
}

rule INDICATOR_KB_CERT_0086909b91f07f9316984d888d1e28ab76 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5eba3c38e989c7d16c987e2989688d3bd24032bc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dantherm Intelligent Monitoring A/S" and
            pe.signatures[i].serial == "00:86:90:9b:91:f0:7f:93:16:98:4d:88:8d:1e:28:ab:76"
        )
}

rule INDICATOR_KB_CERT_00d4ef1ab6ab5d3cb35e4efb7984def7a2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "10d82c75a1846ebfb2a0d1abe9c01622bdfabf0a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REIGN BROS ApS" and
            pe.signatures[i].serial == "00:d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2"
        )
}

rule INDICATOR_KB_CERT_13039da3b2924b7a8b0a2ac4637c2efa {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ad9fa264674c152b2298533e41e098bcaa0345af"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Tekhnokom" and
            pe.signatures[i].serial == "13:03:9d:a3:b2:92:4b:7a:8b:0a:2a:c4:63:7c:2e:fa"
        )
}

rule INDICATOR_KB_CERT_2abd2eef14d480dfea9ca9fdd823cf03 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "db3d9ccf11d8b0d4f33cf4dc93689fdd942f8fbe"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BE SOL d.o.o." and
            pe.signatures[i].serial == "2a:bd:2e:ef:14:d4:80:df:ea:9c:a9:fd:d8:23:cf:03"
        )
}

rule INDICATOR_KB_CERT_08622b9dd9d78e67678ecc21e026522e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a7d86073742ea55af134e07a00aefa355dc123be"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kayak Republic af 2015 APS" and
            pe.signatures[i].serial == "08:62:2b:9d:d9:d7:8e:67:67:8e:cc:21:e0:26:52:2e"
        )
}

rule INDICATOR_KB_CERT_5a17d5de74fd8f09df596df3123139bb {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1da887a57dddd7376a18f75841559c9682f78b04"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ACTA FIS d.o.o." and
            pe.signatures[i].serial == "5a:17:d5:de:74:fd:8f:09:df:59:6d:f3:12:31:39:bb"
        )
}

rule INDICATOR_KB_CERT_15da61d7e1a631803431561674fb9b90 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9a9bc3974e3cbbabdeb2b6debdc0455586e128a4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JAY DANCE STUDIO d.o.o." and
            pe.signatures[i].serial == "15:da:61:d7:e1:a6:31:80:34:31:56:16:74:fb:9b:90"
        )
}

rule INDICATOR_KB_CERT_58aa64564a50e8b2d6e31d5cd6250fde {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a7b43a5190e6a72c68e20f661f69ddc24b5a2561"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Foreground" and
            pe.signatures[i].serial == "58:aa:64:56:4a:50:e8:b2:d6:e3:1d:5c:d6:25:0f:de"
        )
}

rule INDICATOR_KB_CERT_00bbd4dc3768a51aa2b3059c1bad569276 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "36936c4aa401c3bbeb227ce5011ec3bdc02fdd14"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JJ ELECTRICAL SERVICES LIMITED" and
            pe.signatures[i].serial == "00:bb:d4:dc:37:68:a5:1a:a2:b3:05:9c:1b:ad:56:92:76"
        )
}

rule INDICATOR_KB_CERT_3a236f003bdefc0c55aa42d9c6c0b08e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5ba147ebae6089f99823b1640c305b337b1a4c36"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Assurio" and
            pe.signatures[i].serial == "3a:23:6f:00:3b:de:fc:0c:55:aa:42:d9:c6:c0:b0:8e"
        )
}

rule INDICATOR_KB_CERT_010000000001302693cb45 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "bc5fcb5a2b5e0609e2609cff5e272330f79b2375"
        hash = "74069d20e8b8299590420c9af2fdc8856c14d94929c285948585fc89ab2f938f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AutoIt Consulting Ltd" and
            pe.signatures[i].serial == "01:00:00:00:00:01:30:26:93:cb:45"
        )
}

rule INDICATOR_KB_CERT_0407abb64e9990180789eacb81f5f914 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "bcb40c7d23c9db41766c780b5388fb70f3d570bf"
        hash = "f1fdac82e4e4da91ba2a9d8122a5f27e11a8342308b18376b189d2cc7468557b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VideoLAN" and
            pe.signatures[i].serial == "04:07:ab:b6:4e:99:90:18:07:89:ea:cb:81:f5:f9:14"
        )
}

rule INDICATOR_KB_CERT_3f8d23c136ae9cbeeac7605b24ec0391 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ff481ea6a887f3b5b941ff7d99a6cdf90c814c40"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bandicam Company" and
            pe.signatures[i].serial == "3f:8d:23:c1:36:ae:9c:be:ea:c7:60:5b:24:ec:03:91"
        )
}

rule INDICATOR_KB_CERT_3972443af922b751d7d36c10dd313595 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d89e3bd43d5d909b47a18977aa9d5ce36cee184c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sore Loser Games ApS" and
            pe.signatures[i].serial == "39:72:44:3a:f9:22:b7:51:d7:d3:6c:10:dd:31:35:95"
        )
}

rule INDICATOR_KB_CERT_37f3384b16d4eef0a9b3344b50f1d8a3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3fcdcf15c35ef74dc48e1573ad1170b11a623b40"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sore Loser Games ApS" and
            pe.signatures[i].serial == "37:f3:38:4b:16:d4:ee:f0:a9:b3:34:4b:50:f1:d8:a3"
        )
}

rule INDICATOR_KB_CERT_00b3969cd6b2f913acc99c3f61fc14852f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "bd9cadcfb5cde90f493a92e43f49bf99db177724"
        hash1 = "a4d9cf67d111b79da9cb4b366400fc3ba1d5f41f71d48ca9c8bb101cb4596327"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "S.O.M GmbH" and
            (
                pe.signatures[i].serial == "b3:96:9c:d6:b2:f9:13:ac:c9:9c:3f:61:fc:14:85:2f" or
                pe.signatures[i].serial == "00:b3:96:9c:d6:b2:f9:13:ac:c9:9c:3f:61:fc:14:85:2f"
            )
        )
}

rule INDICATOR_KB_CERT_0d83e7f47189cdbfc7fa3e5f58882329 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ba4bf6d8caac468c92dd7cd4303cbdb2c9f58886"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and
            pe.signatures[i].serial == "0d:83:e7:f4:71:89:cd:bf:c7:fa:3e:5f:58:88:23:29"
        )
}

rule INDICATOR_KB_CERT_008385684419ab26a3f2640b1496e1fe94 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ee1d7d90957f3f2ccfcc069f5615a5bafdac322f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CAUSE FOR CHANGE LTD" and
            pe.signatures[i].serial == "00:83:85:68:44:19:ab:26:a3:f2:64:0b:14:96:e1:fe:94"
        )
}

rule INDICATOR_KB_CERT_1aec3d3f752a38617c1d7a677d0b5591 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1d41b9f7714f221d76592e403d2fbb0f0310e697"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SILVER d.o.o." and
            pe.signatures[i].serial == "1a:ec:3d:3f:75:2a:38:61:7c:1d:7a:67:7d:0b:55:91"
        )
}

rule INDICATOR_KB_CERT_e5b2af04ea4b84a94609a47eba3164ec {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7785d50066faee71d1a463584c1a97f34431ddfe"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RRGRQJRWZHRTLFAUVK" and
            pe.signatures[i].serial == "e5:b2:af:04:ea:4b:84:a9:46:09:a4:7e:ba:31:64:ec"
        )
}

rule INDICATOR_KB_CERT_Dummy01 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint1 = "16b7eb40b97149f49e8ec885b0a7fa7598f5a00f"
        thumbprint2 = "902bf957b57f134619443d80cb8767250e034110"
        thumbprint3 = "505f0055a66216c81420f41335ea7a4eb7b240fe"
        thumbprint4 = "c05a6806d770dcec780e0477b83f068a1082be06"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dummy certificate" and
            pe.signatures[i].serial == "01"
        )
}

rule INDICATOR_KB_CERT_00a7e1dc5352c3852c5523030f57f2425c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "09232474b95fc2cfb07137e1ada82de63ffe6fcd"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pushka LLC" and
            pe.signatures[i].serial == "00:a7:e1:dc:53:52:c3:85:2c:55:23:03:0f:57:f2:42:5c"
        )
}

rule INDICATOR_KB_CERT_635517466b67bd4bba805bc67ac3328c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0b3144ec936028cbf5292504ef2a75eea8eb6c1d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MEDIATEK INC." and
            pe.signatures[i].serial == "63:55:17:46:6b:67:bd:4b:ba:80:5b:c6:7a:c3:32:8c"
        )
}

rule INDICATOR_KB_CERT_62e745e92165213c971f5c490aea12a5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0120553d101d8cf28489570a516bd16dacda4add"
        hash = "f631405eb61bdf6f6e34657e5b99273743e1e24854942166a16f38728e19f200"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NVIDIA Corporation" and
            pe.signatures[i].serial == "62:e7:45:e9:21:65:21:3c:97:1f:5c:49:0a:ea:12:a5"
        )
}

rule INDICATOR_KB_CERT_a2253aeb5b0ff1aecbfd412c18ccf07a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b03db8e908dcf0e00a5a011ba82e673d91524816"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Gallopers Software Solutions Limited" and
            pe.signatures[i].serial == "a2:25:3a:eb:5b:0f:f1:ae:cb:fd:41:2c:18:cc:f0:7a"
        )
}

rule INDICATOR_KB_CERT_21e3cae5b77c41528658ada08509c392 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8acfaa12e5d02c1e0daf0a373b0490d782ea5220"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Network Design International Holdings Limited" and
            pe.signatures[i].serial == "21:e3:ca:e5:b7:7c:41:52:86:58:ad:a0:85:09:c3:92"
        )
}

/*
rule INDICATOR_KB_CERT_0c15be4a15bb0903c901b1d6c265302f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "cb7e84887f3c6015fe7edfb4f8f36df7dc10590e"
        hash = "2065157b834e1116abdd5d67167c77c6348361e04a8085aa382909500f1bbe69"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Google LLC" and
            pe.signatures[i].serial == "0c:15:be:4a:15:bb:09:03:c9:01:b1:d6:c2:65:30:2f"
        )
}
*/

/*
rule INDICATOR_KB_CERT_06aea76bac46a9e8cfe6d29e45aaf033 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a3958ae522f3c54b878b20d7b0f63711e08666b2"
        hash1 = "dd9fd40438d1819fb9f9d72ddc6f5d06c1651aa6543ca6560819d27a764c68d2"
        hash2 = "89b4b266845420410683c6452a44e0aba4102d0f0e153893a2d1f74d047b6f0a"
        hash3 = "38afc740c217820b823c5466d8c1166bdf978aefba8a9913019ab58ee595499b"
        hash4 = "3debc14f1fabd52b0a8ef2b7b6ec57c6433b94e932e0945910c03b7f69f2fdf8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Google LLC" and
            pe.signatures[i].serial == "06:ae:a7:6b:ac:46:a9:e8:cf:e6:d2:9e:45:aa:f0:33"
        )
}
*/

rule INDICATOR_KB_CERT_09b3a7e559fcb024c4b66b794e9540cb {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "59c60ade491c9eda994711b1fdb59510baad2ea3"
        hash1 = "b57d694b6d1f9e0634953e8f5c1e4faf84fb50be806a8887dd5b31bfd58a167f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Windscribe Limited" and
            pe.signatures[i].serial == "09:b3:a7:e5:59:fc:b0:24:c4:b6:6b:79:4e:95:40:cb"
        )
}

rule INDICATOR_KB_CERT_19beff8a6c129663e5e8c18953dc1f67 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ad3deacd821fee3bb158665bd7fa491e39aab2e6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CULNADY LTD LTD" and
            pe.signatures[i].serial == "19:be:ff:8a:6c:12:96:63:e5:e8:c1:89:53:dc:1f:67"
        )
}

rule INDICATOR_KB_CERT_0cf2d0b5bfdd68cf777a0c12f806a569 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0c212cdf3d9a46621c19af5c494ff6bad25d3190"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PROTIP d.o.o." and
            pe.signatures[i].serial == "0c:f2:d0:b5:bf:dd:68:cf:77:7a:0c:12:f8:06:a5:69"
        )
}

rule INDICATOR_KB_CERT_56f008e69a7c4c3feb389c66eaf58259 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a7dc8cb973ef5f54af0889549d84dee51a7db839"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MEDIATEK INC." and
            pe.signatures[i].serial == "56:f0:08:e6:9a:7c:4c:3f:eb:38:9c:66:ea:f5:82:59"
        )
}

rule INDICATOR_KB_CERT_028aa6e7b516c0d155f15d6290a430e3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "adc0e27a6076311553127e50969b7862d3384d35"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Discord Inc." and
            pe.signatures[i].serial == "02:8a:a6:e7:b5:16:c0:d1:55:f1:5d:62:90:a4:30:e3"
        )
}

// Fake Flash Player, fake [insert software here] installer/player/setup/etc.
rule INDICATOR_KB_CERT_279b3a26f16a069aa7bca1811d44ad9b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4a9fc15f1d63145b622989c4f5bec4612095401e"
        hash1 = "fc642048d9f0b8cb36649fd377fdb68dce3998f2a88e8c64acdc4e88435f2562"
        hash2 = "914067034336e4ed8b56e66d6be29f34477d9fb38ba73095a3edca5ec9cb1a9c"
        hash3 = "daf7e148f82807808cac8a21b1a3ce43491c3a140420442a1c1ee2d497a9e0a2"
        hash4 = "3727044bebe4a14aed66df5119c11471a57b50c57ab4baaef4073323206d3b9b"
        hash5 = "f0239d16f77b11e6b606b23a53c9e563f6360a27a03c0b9cf83b151ee8ee9088"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DIGITAL DEVLIN LIMITED" and
            pe.signatures[i].serial == "27:9b:3a:26:f1:6a:06:9a:a7:bc:a1:81:1d:44:ad:9b"
        )
}

rule INDICATOR_KB_CERT_07cef66a71c35bc3aed6d100c6493863 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9f65b1f0bed6e58ecdcc30b81b08b350fcc966a1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fubon Technologies Ltd" and
            pe.signatures[i].serial == "07:ce:f6:6a:71:c3:5b:c3:ae:d6:d1:00:c6:49:38:63"
        )
}

rule INDICATOR_KB_CERT_00d3356318924c8c42959bf1d1574e6482 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e21f261f5cf7c2856bd9da5a5ed2c4e2b2ef4c9a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ADV TOURS d.o.o." and
            pe.signatures[i].serial == "00:d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82"
        )
}

rule INDICATOR_KB_CERT_038fc745523b41b40d653b83aa381b80 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "05124a4a385b4b2d7a9b58d1c3ad7f2a84e7b0af"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Optima" and
            pe.signatures[i].serial == "03:8f:c7:45:52:3b:41:b4:0d:65:3b:83:aa:38:1b:80"
        )
}

rule INDICATOR_KB_CERT_00ac0a7b9420b369af3ddb748385b981 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "15b56f8b0b22dbc7c08c00d47ee06b04fa7df5fe"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Tochka" and
            pe.signatures[i].serial == "00:ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81"
        )
}

rule INDICATOR_KB_CERT_00913ba16962cd7eee25965a6d0eeffa10 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "079aeb295c8e27ac8d9be79c8b0aaf66a0ef15de"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JMT TRADING GROUP INC" and
            pe.signatures[i].serial == "00:91:3b:a1:69:62:cd:7e:ee:25:96:5a:6d:0e:ef:fa:10"
        )
}

rule INDICATOR_KB_CERT_f44a91704f9ea388446d2635f2a8c8a5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "573514c39bcef5690ab924f9df30577def6e877f"
        hash1 = "d67dde5621d6de76562bc2812f04f986b441601b088aa936d821c0504eb4f7aa"
        hash2 = "71f60a985d2cc9fc47c6845a88eea4da19303a96a2ff69daae70276f70dcdae0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Binance" and
            pe.signatures[i].serial == "f4:4a:91:70:4f:9e:a3:88:44:6d:26:35:f2:a8:c8:a5"
        )
}

rule INDICATOR_KB_CERT_029685cda1c8233d2409a31206f78f9f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "86574b0ef7fbce15f208bf801866f34c664cf7ce"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KOTO TRADE" and
            pe.signatures[i].serial == "02:96:85:cd:a1:c8:23:3d:24:09:a3:12:06:f7:8f:9f"
        )
}

rule INDICATOR_KB_CERT_00aebe117a13b8bca21685df48c74f584d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4dc9713dfb079fbae4173d342ebeb4efb9b0a4dc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NANAX d.o.o." and
            pe.signatures[i].serial == "00:ae:be:11:7a:13:b8:bc:a2:16:85:df:48:c7:4f:58:4d"
        )
}

rule INDICATOR_KB_CERT_38989ec61ecdb7391ff5647f7d58ad18 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "71e74a735c72d220aa45e9f1b83f0b867f2da166"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RotA Games ApS" and
            pe.signatures[i].serial == "38:98:9e:c6:1e:cd:b7:39:1f:f5:64:7f:7d:58:ad:18"
        )
}

rule INDICATOR_KB_CERT_00d08d83ff118df3777e371c5c482cce7b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8a1bcf92ea961b8bc8817b0630f34607ccb5bff2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMO-K Limited Liability Company" and
            pe.signatures[i].serial == "00:d0:8d:83:ff:11:8d:f3:77:7e:37:1c:5c:48:2c:ce:7b"
        )
}

rule INDICATOR_KB_CERT_249e3f1b7595e7d0fe6df13303287343 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8e99b2786f59e543d1f3d02d140e35342c55c18a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "gsLPuSUgRZueWihiZHqYBriNSQqS" and
            pe.signatures[i].serial == "24:9e:3f:1b:75:95:e7:d0:fe:6d:f1:33:03:28:73:43"
        )
}

rule INDICATOR_KB_CERT_31d852f5fca1a5966b5ed08a14825c54 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a657b8f2efea32e6a1d46894764b7a4f82ad0b56"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BBT KLA d.o.o." and
            pe.signatures[i].serial == "31:d8:52:f5:fc:a1:a5:96:6b:5e:d0:8a:14:82:5c:54"
        )
}

rule INDICATOR_KB_CERT_510c5e540503f30c9caa3082296aa452 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3e56a13ceb87243b8b2c5de67da54a3a9e0988d7"
        hash = "cb01f31a322572035cf19f6cda00bcf1d8235dcc692588810405d0fc6e8d239c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Systems Analysis 360 Ltd" and
            pe.signatures[i].serial == "51:0c:5e:54:05:03:f3:0c:9c:aa:30:82:29:6a:a4:52"
        )
}

rule INDICATOR_KB_CERT_56bba7fe242e6b49695bcf07870f5f5e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3c176bff246a30460311e8c71f880cad2a845164"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ewGMiQgCHj" and
            pe.signatures[i].serial == "56:bb:a7:fe:24:2e:6b:49:69:5b:cf:07:87:0f:5f:5e"
        )
}

rule INDICATOR_KB_CERT_00dfef1a8c0dbfef64bc6c8a0647d6e873 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0709cdcb27230171877e2a11e6646a9fde28e02c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NnTqRHlSFNJSUHGaiKWzqyHGdPzBarblmWEzpKHvkZrqn" and
            pe.signatures[i].serial == "00:df:ef:1a:8c:0d:bf:ef:64:bc:6c:8a:06:47:d6:e8:73"
        )
}

rule INDICATOR_KB_CERT_0609b5aad2dfb81fbe6b75e4cfe372a6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a30013d7a055c98c4bfa097fe85110629ef13e67"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "vVBhgeghjdigSdWYSAdmy" and
            pe.signatures[i].serial == "06:09:b5:aa:d2:df:b8:1f:be:6b:75:e4:cf:e3:72:a6"
        )
}

rule INDICATOR_KB_CERT_02b6656292310b84022db5541bc48faf {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "bb58a3d322fd67122804b2924ad1ddc27016e11a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DILA d.o.o." and
            pe.signatures[i].serial == "02:b6:65:62:92:31:0b:84:02:2d:b5:54:1b:c4:8f:af"
        )
}

rule INDICATOR_KB_CERT_00d609b6c95428954a999a8a99d4f198af {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b1d8033dd7ad9e82674299faed410817e42c4c40"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Fudl" and
            pe.signatures[i].serial == "00:d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af"
        )
}

rule INDICATOR_KB_CERT_6a568f85de2061f67ded98707d4988df {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ed7e16a65294086fbdeee09c562b0722fdb2db48"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Apladis" and
            pe.signatures[i].serial == "6a:56:8f:85:de:20:61:f6:7d:ed:98:70:7d:49:88:df"
        )
}

rule INDICATOR_KB_CERT_f90e68cbf92fd7ad409e281c3f2a0f0a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c202564339ddd78a1ce629ce54824ba2697fa3d6"
        hash = "d79a8f491c0112c3f26572350336fe7d22674f5550f37894643eba980ae5bd32"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SUCK-MY-DICK-ESET" and
            pe.signatures[i].serial == "f9:0e:68:cb:f9:2f:d7:ad:40:9e:28:1c:3f:2a:0f:0a"
        )
}

rule INDICATOR_KB_CERT_7ddd3796a427b42f2e52d7c7af0ca54f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b5cd5a485dee4a82f34c98b3f108579e8501fdea"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Fobos" and
            pe.signatures[i].serial == "7d:dd:37:96:a4:27:b4:2f:2e:52:d7:c7:af:0c:a5:4f"
        )
}

rule INDICATOR_KB_CERT_17d99cc2f5b29522d422332e681f3e18 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "969932039e8bf3b4c71d9a55119071cfa1c4a41b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PKV Trading ApS" and
            pe.signatures[i].serial == "17:d9:9c:c2:f5:b2:95:22:d4:22:33:2e:68:1f:3e:18"
        )
}

rule INDICATOR_KB_CERT_02de1cc6c487954592f1bf574ca2b000 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e35804bbf4573f492c51a7ad7a14557816fe961f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Orca System" and
            pe.signatures[i].serial == "02:de:1c:c6:c4:87:95:45:92:f1:bf:57:4c:a2:b0:00"
        )
}

rule INDICATOR_KB_CERT_142aac4217e22b525c8587589773ba9b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b15a4189dcbb27f9b7ced94bc5ca40b7e62135c3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].serial == "14:2a:ac:42:17:e2:2b:52:5c:85:87:58:97:73:ba:9b"
        )
}

rule INDICATOR_KB_CERT_26279f0f2f11970dccf63eba88f2d4c4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d4fb2982268b592e3cd46fa78194e71418297741"
        hash = "a3af3d7e825daeffc05e34a784d686bb9f346d48a92c060e1e901c644398d5d7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Qihoo 360 Software (Beijing) Company Limited" and
            pe.signatures[i].serial == "26:27:9f:0f:2f:11:97:0d:cc:f6:3e:ba:88:f2:d4:c4"
        )
}

rule INDICATOR_KB_CERT_23389161e45a218bd24e6e859ae11153 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "978859ce5698f2bfade1129401cf70856be738d3"
        hash = "a3af3d7e825daeffc05e34a784d686bb9f346d48a92c060e1e901c644398d5d7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Qihoo 360 Software (Beijing) Company Limited" and
            pe.signatures[i].serial == "23:38:91:61:e4:5a:21:8b:d2:4e:6e:85:9a:e1:11:53"
        )
}

rule INDICATOR_KB_CERT_4026d6291f1ac7cf86c2c81172cfb200 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2ae4328db08bac015d8965e325b0263c0809d93e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MztxUCVYqnxgsyqVryViRnMfHFYBgyVMXkXuVGqmyPx" and
            pe.signatures[i].serial == "40:26:d6:29:1f:1a:c7:cf:86:c2:c8:11:72:cf:b2:00"
        )
}

rule INDICATOR_KB_CERT_00b0a308fc2e71ac4ac40677b9c27ccbad {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "15e502f1482a280f7285168bb5e227ffde4e41a6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Volpayk LLC" and
            pe.signatures[i].serial == "00:b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad"
        )
}

rule INDICATOR_KB_CERT_009ecaa6e28e7615ef5a12d87e327264c0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "50899ef5014af31cd54cb9a7c88659a6890b6954"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HaqMkgGQmnNHpFsQmzMRDcavkPBzOcvMatDmcLHuDNoiQWMqj" and
            pe.signatures[i].serial == "00:9e:ca:a6:e2:8e:76:15:ef:5a:12:d8:7e:32:72:64:c0"
        )
}

rule INDICATOR_KB_CERT_19985190b09206952efd412d3ccc18e2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "49ec0580239c07da4ffba56dc8617a8c94119c69"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "cwcpbvBhYEPeJYcCNDldHTnGK" and
            pe.signatures[i].serial == "19:98:51:90:b0:92:06:95:2e:fd:41:2d:3c:cc:18:e2"
        )
}

rule INDICATOR_KB_CERT_03b27d7f4ee21a462a064a17eef70d6c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a278b5c8a9798ee3b3299ec92a4ab618016628ee"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CCL TRADING LIMITED" and
            pe.signatures[i].serial == "03:b2:7d:7f:4e:e2:1a:46:2a:06:4a:17:ee:f7:0d:6c"
        )
}

rule INDICATOR_KB_CERT_66f98881fbb02d0352bef7c13bd61df2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "722eee34153fc67ea7abdcb0c6e9e54479f1580e"
        hash = "f265524fb9a4a58274dbd32b2ed0c3f816c5eff05e1007a2e7bba286b8ffa72c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].serial == "66:f9:88:81:fb:b0:2d:03:52:be:f7:c1:3b:d6:1d:f2"
        )
}

rule INDICATOR_KB_CERT_3f8b1d4c656982a34435f971c9f3c301 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f12a12ac95e5c4fa9948dd743cc0e81e46c5222e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Word" and
            pe.signatures[i].serial == "3f:8b:1d:4c:65:69:82:a3:44:35:f9:71:c9:f3:c3:01"
        )
}

rule INDICATOR_KB_CERT_00ef9d0cf071d463cd63d13083046a7b8d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "346849dfdeb9bb1a97d98c62d70c578dacbcf30c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rubin LLC" and
            pe.signatures[i].serial == "00:ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d"
        )
}

rule INDICATOR_KB_CERT_00e1e7e596f8f5ccbeed4ab882b6cfe6ce {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4fec400152db868b07f202fd76366332aedc7b78"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LnvNzpvYjsjJOwcvwfalIvRAJHVApnpJU" and
            pe.signatures[i].serial == "00:e1:e7:e5:96:f8:f5:cc:be:ed:4a:b8:82:b6:cf:e6:ce"
        )
}

rule INDICATOR_KB_CERT_047801d5b55c800b48411fd8c320ca5b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "00c49b8d6fd7d2aa26faad8e5a31f93a15d66d09"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LICHFIELD STUDIO GLASS LIMITED" and
            pe.signatures[i].serial == "04:78:01:d5:b5:5c:80:0b:48:41:1f:d8:c3:20:ca:5b"
        )
}

/*
Disabled due to FPs

rule INDICATOR_KB_CERT_07be8f83f4455021f4e24fb021fca24a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "30f505c955e9b503416e64f05325bfa6cb6e2dff"
        hash = "35375028a2cc4876b5a8476876ad75a037b8c4e303589ce6e9d9c61aaba9f74c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kaspersky Lab" and
            pe.signatures[i].serial == "07:be:8f:83:f4:45:50:21:f4:e2:4f:b0:21:fc:a2:4a"
        )
}
*/

rule INDICATOR_KB_CERT_ceb6b2eec12934a64f75a4592159f084 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ccd30b68e37fc177b754250767a16062a711310a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WMade by H5et.com" and
            pe.signatures[i].serial == "ce:b6:b2:ee:c1:29:34:a6:4f:75:a4:59:21:59:f0:84"
        )
}

rule INDICATOR_KB_CERT_6b6739e55f3f25b147c4a6767de41f57 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "07a09d3d3c05918519d6f357fe7eed5e1d529f22"
        hash = "da0921c1e416b3734272dfa619f88c8cd32e9816cdcbeeb81d9e2b2e8a95af4c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Avast Antivirus SEC" and
            pe.signatures[i].serial == "6b:67:39:e5:5f:3f:25:b1:47:c4:a6:76:7d:e4:1f:57"
        )
}

rule INDICATOR_KB_CERT_00b97f66bb221772dc07ef1d4bed8f6085 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "fb4efb3bfcef8e9a667c8657f2e3c8fb7436666e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "S-PRO d.o.o." and
            pe.signatures[i].serial == "00:b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85"
        )
}

rule INDICATOR_KB_CERT_00cc95d6ebf18a3711e196aea210465a19 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "319f0e03f0f230629258c7ea05e7d56ead830ce9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GEN Sistemi, d.o.o." and
            pe.signatures[i].serial == "00:cc:95:d6:eb:f1:8a:37:11:e1:96:ae:a2:10:46:5a:19"
        )
}

rule INDICATOR_KB_CERT_dde89c647dc2138244228040e324dc77 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1d9aaa1bc7d6fc5a76295dd1cf692fe4a1283f04"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WMade by H5et.com" and
            pe.signatures[i].serial == "dd:e8:9c:64:7d:c2:13:82:44:22:80:40:e3:24:dc:77"
        )
}

rule INDICATOR_KB_CERT_00fed006fbf85cd1c6ba6b4345b198e1e6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4bc67aca336287ff574978ef3bf67c688f6449f2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LoL d.o.o." and
            pe.signatures[i].serial == "00:fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6"
        )
}

rule INDICATOR_KB_CERT_4e7545c9fc5938f5198ab9f1749ca31c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7a49677c535a13d0a9b6deb539d084ff431a5b54"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "For M d.o.o." and
            pe.signatures[i].serial == "4e:75:45:c9:fc:59:38:f5:19:8a:b9:f1:74:9c:a3:1c"
        )
}

rule INDICATOR_KB_CERT_040f11f124a73bdecc41259845a8a773 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6f332f7e78cac4a6c35209fde248ef317f7a23e8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TrustPort" and
            pe.signatures[i].serial == "04:0f:11:f1:24:a7:3b:de:cc:41:25:98:45:a8:a7:73"
        )
}

rule INDICATOR_KB_CERT_1b1e87e90519d7273c0033bf489b798f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ef09824554f85603c9ffb1cecbfe06ae489a9583"
        hash = "84cef0aed269e6213bfa213d95a3db625bcdde130f33bf4227436985e4473252"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IBIS, OOO" and
            pe.signatures[i].serial == "1b:1e:87:e9:05:19:d7:27:3c:00:33:bf:48:9b:79:8f"
        )
}

rule INDICATOR_KB_CERT_00d9e834182dec62c654e775e809ac1d1b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5bb983693823dbefa292c86d93b92a49ec6f9b26"
        hash = "645dbb6df97018fafb4285dc18ea374c721c86349cb75494c7d63d6a6afc27e6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FoodLehto Oy" and
            pe.signatures[i].serial == "00:d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b"
        )
}

rule INDICATOR_KB_CERT_0ced87bd70b092cb93b182fac32655f6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "97b7602ed71480756cf6e4658a107f8278a48096"
        hash = "083d5efb4da09432a206cb7fba5cef2c82dd6cc080015fe69c2b36e71bca6c89"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Creator Soft Limited" and
            pe.signatures[i].serial == "0c:ed:87:bd:70:b0:92:cb:93:b1:82:fa:c3:26:55:f6"
        )
}

rule INDICATOR_KB_CERT_1afd1491d52f89ba41fa6c0281bb9716 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e4362228dd69c25c1d4ba528549fa00845a8dc24"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TestCert" and
            pe.signatures[i].serial == "1a:fd:14:91:d5:2f:89:ba:41:fa:6c:02:81:bb:97:16"
        )
}

rule INDICATOR_KB_CERT_719ac44966d05762ef95245eefcf3046 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "57ecdfa48ed03a5a8177887090b3d1ffaf124846"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "jZQtQDMvyDRzWsoVFeitFmeNcWMtKauvidXSUrSEwqmi" and
            pe.signatures[i].serial == "71:9a:c4:49:66:d0:57:62:ef:95:24:5e:ef:cf:30:46"
        )
}

rule INDICATOR_KB_CERT_008fe807310d98357a59382090634b93f0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "acd6cf38d03c355ddb84b96a7365bfc1738a0ec5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MAVE MEDIA" and
            pe.signatures[i].serial == "00:8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0"
        )
}

rule INDICATOR_KB_CERT_00801689896ed339237464a41a2900a969 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9b0ab2e7f3514f6372d14b1f7f963c155b18bd24"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GLG Rental ApS" and
            pe.signatures[i].serial == "00:80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69"
        )
}

rule INDICATOR_KB_CERT_Podangers {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6e757c3b91d75d58b5230c27a2fcc01bfe5fe60f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PODANGERS" and
            pe.signatures[i].serial == "00"
        )
}

rule INDICATOR_KB_CERT_00e9a1e07314bc2f2d51818454b63e5829 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3a146f3c0fc17b9df14bd127ebf12b15a5a1a011"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "iWLiYpLtpOlZYGmysAZkhz" and
            pe.signatures[i].serial == "00:e9:a1:e0:73:14:bc:2f:2d:51:81:84:54:b6:3e:58:29"
        )
}

rule INDICATOR_KB_CERT_9d915138acdac1a044afa6e5d99567c5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4f8b9ce0e25810d1b62d8c016607de128beba2a1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AAAruntest" and
            pe.signatures[i].serial == "9d:91:51:38:ac:da:c1:a0:44:af:a6:e5:d9:95:67:c5"
        )
}

rule INDICATOR_KB_CERT_11a9bf6b2dcbc683475b431a1c79133e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7412b3f5ba689967a5b46e6ef5dc5e9b9de3917d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BINDOX" and
            pe.signatures[i].serial == "11:a9:bf:6b:2d:cb:c6:83:47:5b:43:1a:1c:79:13:3e"
        )
}

rule INDICATOR_KB_CERT_3fd3661533eef209153c9afec3ba4d8a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "20ddd23f53e1ac49926335ec3e685a515ab49252"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SFB Regnskabsservice ApS" and
            pe.signatures[i].serial == "3f:d3:66:15:33:ee:f2:09:15:3c:9a:fe:c3:ba:4d:8a"
        )
}

rule INDICATOR_KB_CERT_2ba40f65086686dd4ab7171e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "842f81869c2f4f2ba2a7e6513501166e2679108a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RITEIL SISTEMS LLC" and
            pe.signatures[i].serial == "2b:a4:0f:65:08:66:86:dd:4a:b7:17:1e"
        )
}

rule INDICATOR_KB_CERT_67144b9ed89fb2d106d0233873c6e35f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5971faead4c86bf72e6ab36efc0376d4abfffeda"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Infosignal LLC" and
            pe.signatures[i].serial == "67:14:4b:9e:d8:9f:b2:d1:06:d0:23:38:73:c6:e3:5f"
        )
}

rule INDICATOR_KB_CERT_00ca4822e6905aa4fca9e28523f04f14a3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "35ced9662401f10fa92282e062a8b5588e0c674d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ELISTREID, OOO" and
            pe.signatures[i].serial == "00:ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3"
        )
}

rule INDICATOR_KB_CERT_3769815a97a8fb411e005282b37878e3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c80fd3259af331743e35a2197f5f57061654860c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Yandex" and
            pe.signatures[i].serial == "37:69:81:5a:97:a8:fb:41:1e:00:52:82:b3:78:78:e3"
        )
}

rule INDICATOR_KB_CERT_3b007314844b114c61bc156a0609a286 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "52ae9fdda7416553ab696388b66f645e07e753cd"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SATURDAY CITY LIMITED" and
            pe.signatures[i].serial == "3b:00:73:14:84:4b:11:4c:61:bc:15:6a:06:09:a2:86"
        )
}

rule INDICATOR_KB_CERT_262ca7ae19d688138e75932832b18f9d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c5d34eb26bbb3fcb274f9e9cb37f5ae6612747a1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bisoyetutu Ltd Ltd" and
            pe.signatures[i].serial == "26:2c:a7:ae:19:d6:88:13:8e:75:93:28:32:b1:8f:9d"
        )
}

rule INDICATOR_KB_CERT_6b0008bbd5eb53f5d9e616c3ed00000008bbd5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a24cff3a026dc6b30fb62fb01dbda704eb07164f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "microsoft.com" and
            pe.signatures[i].serial == "6b:00:08:bb:d5:eb:53:f5:d9:e6:16:c3:ed:00:00:00:08:bb:d5"
        )
}

rule INDICATOR_KB_CERT_6abc3555becca0bc4b6987ccc2ea42b5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a36c75dd80d34020df5632c2939e82d39d2dca64"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jwkwjaagoh" and
            pe.signatures[i].serial == "6a:bc:35:55:be:cc:a0:bc:4b:69:87:cc:c2:ea:42:b5"
        )
}

rule INDICATOR_KB_CERT_3c5fc5d02273f297404f7b9306e447bb {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3fa4a6efd5e443627e9e32e6effe04c991f4fe8f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Wirpool Soft" and
            pe.signatures[i].serial == "3c:5f:c5:d0:22:73:f2:97:40:4f:7b:93:06:e4:47:bb"
        )
}

rule INDICATOR_KB_CERT_1f3216f428f850be2c66caa056f6d821 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d4c89b25d3e92d05b44bc32c0cbfd7693613f3ee"
        hash1 = "954f62f0014b51953056dd668441cd4e116874fd6d6c75bd982ba821ea6744eb"
        hash2 = "8fe09855b5eebc5950fdc427fbbd17b2c757a843de687a4da322987510549eba"
        hash3 = "1fbc3ddcd892c868cab037f43fcee5cd1dd67f5ce0ac882d851603bdc934ec43"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Telegram FZ-LLC" and
            pe.signatures[i].serial == "1f:32:16:f4:28:f8:50:be:2c:66:ca:a0:56:f6:d8:21"
        )
}

rule INDICATOR_KB_CERT_7d36cbb64bc9add17ba71737d3ecceca {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a7287460dcf02e38484937b121ce8548191d4e64"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LTD SERVICES LIMITED" and
            pe.signatures[i].serial == "7d:36:cb:b6:4b:c9:ad:d1:7b:a7:17:37:d3:ec:ce:ca"
        )
}

rule INDICATOR_KB_CERT_00df7139e106dbb68dfe4de97d862af708 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4ac627227a25f0914f3a73ff85d90b45da589329"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "zPfPJHDCzusZRYQYJZGZoFfZmvYtSlFXDPQKtoQzc" and
            pe.signatures[i].serial == "00:df:71:39:e1:06:db:b6:8d:fe:4d:e9:7d:86:2a:f7:08"
        )
}

rule INDICATOR_KB_CERT_00d4f9fc08895654f8bde8d1cc26eff015 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f24af3a784c2316b42854c5853b53d9e556295f7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "kfbdAfVnDMDc" and
            pe.signatures[i].serial == "00:d4:f9:fc:08:89:56:54:f8:bd:e8:d1:cc:26:ef:f0:15"
        )
}

rule INDICATOR_KB_CERT_0393be7fd785ba0e3223a73b15ee6736 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f50fc532839ca7e63315e468c493512db8b7ee83"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FZaKundypKakCIvoMBPpTnwIDUJM" and
            pe.signatures[i].serial == "03:93:be:7f:d7:85:ba:0e:32:23:a7:3b:15:ee:67:36"
        )
}

rule INDICATOR_KB_CERT_008b7369b2f0c313634a1c1dfc4a828a54 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1cad5864bcc0f6aa20b99a081501a104b633dddd"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LFpKdFUgpGKj" and
            pe.signatures[i].serial == "00:8b:73:69:b2:f0:c3:13:63:4a:1c:1d:fc:4a:82:8a:54"
        )
}

rule INDICATOR_KB_CERT_59a57e8ba3dcf2b6f59981fda14b03 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e201821e152d7ae86078c4e6a3a3a1e1c5e29f9a"
        hash1 = "d9ace2d97010316fdb0f416920232e8d4c59b01614633c4d5def79abb15d0175"
        hash2 = "80e363dee08f4f77e5a061c10f18503c7ce802818cf6bb1c8a16da0ba3877b01"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Medium LLC" and
            pe.signatures[i].serial == "59:a5:7e:8b:a3:dc:f2:b6:f5:99:81:fd:a1:4b:03"
        )
}

rule INDICATOR_KB_CERT_00c79f817f082986bef3209f6723c8da97 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e2bf86dc46fca1c35f98ff84d8976be8aa0668bc"
        hash1 = "dd49651e325b04ea14733bcd676c0a1cb58ab36bf79162868ade02b396ec3ab0"
        hash2 = "823cb4b92a1266c880d917c7d6f71da37d524166287b30c0c89b6bb03c2e4b64"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Al-Faris group d.o.o." and
            pe.signatures[i].serial == "00:c7:9f:81:7f:08:29:86:be:f3:20:9f:67:23:c8:da:97"
        )
}

rule INDICATOR_KB_CERT_beb721fcb3274c984479d6554efe8f49 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2d1fd0cce4aa7e7dc6dd114a301825a7b8e887cf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CONFUSER" and
            pe.signatures[i].serial == "be:b7:21:fc:b3:27:4c:98:44:79:d6:55:4e:fe:8f:49"
        )
}

rule INDICATOR_KB_CERT_00c4188d6b70b4bd3b977b19abd04c1157 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "90fefd18c677d6e5ac6db969a7247e3eb0b018df"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PRESTO Co., s.r.o." and
            pe.signatures[i].serial == "00:c4:18:8d:6b:70:b4:bd:3b:97:7b:19:ab:d0:4c:11:57"
        )
}

rule INDICATOR_KB_CERT_00ad255d4ebefa751f3782587396c08629 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8fa4298057066c9ef96c28b2dd065e8896327658"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Ornitek" and
            pe.signatures[i].serial == "00:ad:25:5d:4e:be:fa:75:1f:37:82:58:73:96:c0:86:29"
        )
}

rule INDICATOR_KB_CERT_084b6f19898214a02a5f32e6ea69f0fd {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4b89f40ba2c83c3e65d2be59abb3385cde401581"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TORG-ALYANS, LLC" and
            pe.signatures[i].serial == "08:4b:6f:19:89:82:14:a0:2a:5f:32:e6:ea:69:f0:fd"
        )
}

rule INDICATOR_KB_CERT_24c1ef800f275ab2780280c595de3464 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "836b81154eb924fe741f50a21db258da9b264b85"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HOLGAN LIMITED" and
            pe.signatures[i].serial == "24:c1:ef:80:0f:27:5a:b2:78:02:80:c5:95:de:34:64"
        )
}

rule INDICATOR_KB_CERT_6401831b46588b9d872b02076c3a7b00 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "19fc95ac815865e8b57c80ed21a22e2c0fecc1ff"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ACTIV GROUP ApS" and
            pe.signatures[i].serial == "64:01:83:1b:46:58:8b:9d:87:2b:02:07:6c:3a:7b:00"
        )
}

rule INDICATOR_KB_CERT_0cf1ed2a6ff4bee621efdf725ea174b7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e33dc0787099d92a712894cfef2aaba3f0d65359"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LEVEL LIST SP Z O O" and
            pe.signatures[i].serial == "0c:f1:ed:2a:6f:f4:be:e6:21:ef:df:72:5e:a1:74:b7"
        )
}

rule INDICATOR_KB_CERT_7ed801843fa001b8add52d3a97b25931 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4ee1539c1455f0070d8d04820fb814f8794f84df"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AM El-Teknik ApS" and
            pe.signatures[i].serial == "7e:d8:01:84:3f:a0:01:b8:ad:d5:2d:3a:97:b2:59:31"
        )
}

rule INDICATOR_KB_CERT_0f0ed5318848703405d40f7c62d0f39a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ed91194ee135b24d5df160965d8036587d6c8c35"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SIES UPRAVLENIE PROTSESSAMI, OOO" and
            pe.signatures[i].serial == "0f:0e:d5:31:88:48:70:34:05:d4:0f:7c:62:d0:f3:9a"
        )
}

rule INDICATOR_KB_CERT_537aa4f1bae48f052c3e57c3e2e1ee61 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "15355505a242c44d6c36abab6267cc99219a931c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALPHA AME LIMITED LLP" and
            pe.signatures[i].serial == "53:7a:a4:f1:ba:e4:8f:05:2c:3e:57:c3:e2:e1:ee:61"
        )
}

rule INDICATOR_KB_CERT_61b11ef9726ab2e78132e01bd791b336 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9f7fcfd7e70dd7cd723ac20e5e7cb7aad1ba976b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Skalari" and
            pe.signatures[i].serial == "61:b1:1e:f9:72:6a:b2:e7:81:32:e0:1b:d7:91:b3:36"
        )
}

rule INDICATOR_KB_CERT_e339c8069126aa6313484fea85b4b326f7b8860c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e339c8069126aa6313484fea85b4b326f7b8860c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Germany classer software" and
            pe.signatures[i].serial == "01"
        )
}

/*
FPs encountered
rule INDICATOR_KB_CERT_01342592a0010cb1109c11c0519cfd24 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7649dc70eca74657c1bae0128492098ae47097ff"
        hash = "7c0d31bca17487efc3f743bb9cb5cf56b5f2fae638cf3681fdc692a5809c94be"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Notepad++" and
            pe.signatures[i].serial == "01:34:25:92:a0:01:0c:b1:10:9c:11:c0:51:9c:fd:24"
        )
}
*/

rule INDICATOR_KB_CERT_734d0baf7a6b44743ff852c8ba7a751a7ff0ec73 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "734d0baf7a6b44743ff852c8ba7a751a7ff0ec73"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Transition software (C) 2018" and
            pe.signatures[i].serial == "01"
        )
}

rule INDICATOR_KB_CERT_02fa994d660de659ee9037ecb437d766 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0cb6bde041b58dbd4ec64bd5a3be38c50f17bb3d"
        hash = "0868a2a7b5e276d3a4a40cdef994de934d33d62a689d7207a31fd57d012ef948"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Piriform Software Ltd" and
            pe.signatures[i].serial == "02:fa:99:4d:66:0d:e6:59:ee:90:37:ec:b4:37:d7:66"
        )
}

rule INDICATOR_KB_CERT_0b446546c36525bf5f084f6bbbba7097 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "05cdf79b0effff361dac0363adaa75b066c49de0"
        hash = "3163ffc06848f6c48ac460ab844470ef85a07b847bf187c2c9cb26c14032a1a5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TeamViewer Germany GmbH" and
            pe.signatures[i].serial == "0b:44:65:46:c3:65:25:bf:5f:08:4f:6b:bb:ba:70:97" and
            1608724800 <= pe.signatures[i].not_after
        )
}

rule INDICATOR_KB_CERT_3991d810fb336e5a7d8c2822 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d66e28b6c6a3789f3ee28afbb07e492fbe85f6a7"
        hash = "744bcf7487aaec504d63521abec65f7c605c52e4a0bf511ab61025fd6c90977b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nota Inc." and
            pe.signatures[i].serial == "39:91:d8:10:fb:33:6e:5a:7d:8c:28:22"
        )
}

rule INDICATOR_KB_CERT_00e4e795fd1fd25595b869ce22aa7dc49f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "269f25e6b7c690ae094086bd7825d03b48d4fcb1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OASIS COURT LIMITED" and
            (
                pe.signatures[i].serial == "00:e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f" or
                pe.signatures[i].serial == "e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f"
            )
        )
}

rule INDICATOR_KB_CERT_008e0fa6b464d466df1b267504b04f7b27 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "91707c95044c5badcd51d198bdbe3a7ff3156c35"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ApcWCjFsGXwbWUJrKZ" and
            pe.signatures[i].serial == "00:8e:0f:a6:b4:64:d4:66:df:1b:26:75:04:b0:4f:7b:27"
        )
}

rule INDICATOR_KB_CERT_559cb90fd16e9d1ad375f050ab6a6616 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "78a149f9a04653b01df09743571df938f9873fa5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shenzhen Smartspace Software technology Co.,Limited" and
            pe.signatures[i].serial == "55:9c:b9:0f:d1:6e:9d:1a:d3:75:f0:50:ab:6a:66:16"
        )
}

/*
rule INDICATOR_KB_CERT_3300000187721772155940c709000000000187 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2485a7afa98e178cb8f30c9838346b514aea4769"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Corporation" and
            pe.signatures[i].serial == "33:00:00:01:87:72:17:72:15:59:40:c7:09:00:00:00:00:01:87"
        )
}
*/

/*
rule INDICATOR_KB_CERT_33000000c91909212ebba648810001000000c9 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0480c9444ea631c9bbe497d86a3d27aa940a06f0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Corporation" and
            pe.signatures[i].serial == "33:00:00:00:c9:19:09:21:2e:bb:a6:48:81:00:01:00:00:00:c9"
        )
}
*/

rule INDICATOR_KB_CERT_eb95a7bd7553533d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8d658fd671fa097c3db18906a29e8c1fa45113d9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\x02C\\x02\\x97\\x04\\x17\\x04\\x1e\\x04.\\x02\\x90\\x00g\\x02\\x94\\x02\\xae\\x00p\\x04 \\x00K\\x04J\\x02\\x88\\x042\\x02K\\x02\\xa3" and
            pe.signatures[i].serial == "eb:95:a7:bd:75:53:53:3d"
        )
}

rule INDICATOR_KB_CERT_0a1f3a057a1dce4bf7d76d0c7adf837e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8279b87c89507bc6e209a7bd8b5c24b31fb9a6dc"
        hash = "2df05a70d3ce646285a0f888df15064b4e73034b67e06d9a4f4da680ed62e926"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Qihu Technology Co., Ltd." and
            pe.signatures[i].serial == "0a:1f:3a:05:7a:1d:ce:4b:f7:d7:6d:0c:7a:df:83:7e"
        )
}

rule INDICATOR_KB_CERT_00849ea0945dd2ea2dc3cc2486578a5715 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8c56adfb8fba825aa9a4ab450c71d45b950e55a4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Biglin" and
            pe.signatures[i].serial == "00:84:9e:a0:94:5d:d2:ea:2d:c3:cc:24:86:57:8a:57:15"
        )
}

/*
rule INDICATOR_KB_CERT_0320be3eb866526927f999b97b04346e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "37a0bacb152a547382195095ab33601929877364"
        hash = "f9a7e1e888fadb9d98e593d75f1b76b0809721ad7efbd9882a9a88d45588ceb6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Realtek Semiconductor Corp." and
            pe.signatures[i].serial == "03:20:be:3e:b8:66:52:69:27:f9:99:b9:7b:04:34:6e"
        )
}
*/

rule INDICATOR_KB_CERT_0537f25a88e24cafdd7919fa301e8146 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "922211f5ab4521941d26915aeb82ee728f931082"
        hash = "72ac61e6311f2a6430d005052dbc0cc58587e7b75722b5e34a71081370f4ddd5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Avira Operations GmbH & Co. KG" and
            pe.signatures[i].serial == "05:37:f2:5a:88:e2:4c:af:dd:79:19:fa:30:1e:81:46"
        )
}

rule INDICATOR_KB_CERT_2e4a279bde2eb688e8ab30f5904fa875 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0cdf4e992af760e59f3ea2f1648804d2a2b47bbc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lespeed Technology Co., Ltd" and
            pe.signatures[i].serial == "2e:4a:27:9b:de:2e:b6:88:e8:ab:30:f5:90:4f:a8:75"
        )
}

rule INDICATOR_KB_CERT_fbe6758ae785d7c678a4ad8de5c3f7e6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "bd1958f0306fc8699e829541cd9b8c4fe0e0c6da920932f2cd4d78ed76bda426"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HORUM" and
            pe.signatures[i].serial == "fb:e6:75:8a:e7:85:d7:c6:78:a4:ad:8d:e5:c3:f7:e6"
        )
}

rule INDICATOR_KB_CERT_00a73b6d821f84db4451d6eedd62c42848 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "eca61ad880741629967004bfc40bf8df6c9f0794"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Mht Holding Vinderup ApS" and
            pe.signatures[i].serial == "00:a7:3b:6d:82:1f:84:db:44:51:d6:ee:dd:62:c4:28:48"
        )
}

rule INDICATOR_KB_CERT_500d76b1b4bfaf4a131f027668fea2d3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "fa491e71d98c7e598e32628a6272a005df86b196"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FviSBJQX" and
            pe.signatures[i].serial == "50:0d:76:b1:b4:bf:af:4a:13:1f:02:76:68:fe:a2:d3"
        )
}

rule INDICATOR_KB_CERT_54cd7ae1c27f1421136ed25088f4979a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "acde047c3d7b22f87d0e6d07fe0a3b734ad5f8ac"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABBYMAJUTA LTD LIMITED" and
            pe.signatures[i].serial == "54:cd:7a:e1:c2:7f:14:21:13:6e:d2:50:88:f4:97:9a"
        )
}

rule INDICATOR_KB_CERT_65efa92a4164a3a2d888b5cf8ff073c8 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "928246cd6a0ee66095a43ae06a696b4c63c6ac24"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ghisler Software GmbH" and
            pe.signatures[i].serial == "65:ef:a9:2a:41:64:a3:a2:d8:88:b5:cf:8f:f0:73:c8"
        )
}

rule INDICATOR_KB_CERT_00ad0a958cdf188bed43154a54bf23afba {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7d851e785ad44eb15d5cdf9c33e10fe8f49616e8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RHM Ltd" and
            (
                pe.signatures[i].serial == "ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba" or
                pe.signatures[i].serial == "00:ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba"
            )
        )
}

rule INDICATOR_KB_CERT_05abac07f8d0ce567f7d75ee047efee2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "68b32eac87652af4172e40e3764477437e5a5ce9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ultrareach Internet Corp." and
            pe.signatures[i].serial == "05:ab:ac:07:f8:d0:ce:56:7f:7d:75:ee:04:7e:fe:e2"
        )
}

rule INDICATOR_KB_CERT_62165b335c13a1a847ce9acff2b29368 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c4cfd244d5148c5b03cac093d49af723252b643c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "t55555Prh" and
            pe.signatures[i].serial == "62:16:5b:33:5c:13:a1:a8:47:ce:9a:cf:f2:b2:93:68"
        )
}

/*
rule INDICATOR_KB_CERT_18a686a1229059017a672136ac2e7265 {
    meta:
        author = "ditekSHen"
        description = "Detects Dell vulnerable driver signing certificate"
        thumbprint = "e308e5b7a6f8a24574e08db9f9fa0ad939103910"
        reference1 = "https://www.bleepingcomputer.com/news/security/vulnerable-dell-driver-puts-hundreds-of-millions-of-systems-at-risk/"
        reference2 = "https://www.dell.com/support/kbdoc/ro-ro/000186019/dsa-2021-088-dell-client-platform-security-update-for-dell-driver-insufficient-access-control-vulnerability"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dell Inc." and
            pe.signatures[i].serial == "18:a6:86:a1:22:90:59:01:7a:67:21:36:ac:2e:72:65"
        )
}
*/

rule INDICATOR_KB_CERT_4cdffb4f02c55ae60a099652605da274 {
    meta:
        author = "ditekSHen"
        description = "Enigma Protector Demo Certificate"
        thumbprint = "4a2d33148aadf947775a15f50535842633cc3442"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DEMO" and
            pe.signatures[i].serial == "4c:df:fb:4f:02:c5:5a:e6:0a:09:96:52:60:5d:a2:74"
        )
}

rule INDICATOR_KB_CERT_25ad5ae68c38ad1021086f4ffc8ba470 {
    meta:
        author = "ditekSHen"
        description = "Enigma Protector CA Certificate"
        thumbprint = "a04c0281bc2203a95ef9bd6d9736486449d80905"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Enigma Protector CA" and
            pe.signatures[i].serial == "25:ad:5a:e6:8c:38:ad:10:21:08:6f:4f:fc:8b:a4:70"
        )
}

rule INDICATOR_KB_CERT_277cd16de5d61b9398b645afe41c09c7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "11a18b9ba48e2b715202def00c2005a394786b23"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE SIGN COMPANY LIMITED" and
            pe.signatures[i].serial == "27:7c:d1:6d:e5:d6:1b:93:98:b6:45:af:e4:1c:09:c7"
        )
}

rule INDICATOR_KB_CERT_066276af2f2c7e246d3b1cab1b4aa42e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "dee5ca4be94a8737c85bbee27bd9d81b235fb700"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IQ Trade ApS" and
            pe.signatures[i].serial == "06:62:76:af:2f:2c:7e:24:6d:3b:1c:ab:1b:4a:a4:2e"
        )
}

rule INDICATOR_KB_CERT_289051a83f350a2c600187c99b6c0a73 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4e075adea8c1bcb9d10904203ab81965f4912ff0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HALL HAULAGE LTD LTD" and
            pe.signatures[i].serial == "28:90:51:a8:3f:35:0a:2c:60:01:87:c9:9b:6c:0a:73"
        )
}

rule INDICATOR_KB_CERT_25a28e418ef2d55b87ee715b42afbedb {
    meta:
        author = "ditekSHen"
        description = "VMProtect Software CA Certificate"
        thumbprint = "14e375bd4a40ddd3310e05328dda16e84bac6d34"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Enigma Protector CA" and
            pe.signatures[i].serial == "25:a2:8e:41:8e:f2:d5:5b:87:ee:71:5b:42:af:be:db"
        )
}

rule INDICATOR_KB_CERT_VMProtect_Client {
    meta:
        author = "ditekSHen"
        description = "VMProtect Client Certificate"
        thumbprint1 = "2e20b7079e5d83e7987b2605db160d1561a0c07a"
        hash1 = "284dc48fc2a66a1071117e5f7b2ad68fba4aae69f31cf68b6b950e6205b52dc0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VMProtect Client "
        )
}

rule INDICATOR_KB_CERT_44fe73f320aa8b7b4f5ca910aa22333a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e952eb51416ab15c0a38b64a32348ed40b675043"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Alpeks LLC" and
            pe.signatures[i].serial == "44:fe:73:f3:20:aa:8b:7b:4f:5c:a9:10:aa:22:33:3a"
        )
}

rule INDICATOR_KB_CERT_df45b36c9d0bd248c3f9494e7ca822 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4b1efa2410d9aab12af6c0b624a3738dd06d3353"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MPO STORITVE d.o.o." and
            pe.signatures[i].serial == "df:45:b3:6c:9d:0b:d2:48:c3:f9:49:4e:7c:a8:22"
        )
}

rule INDICATOR_KB_CERT_adbb8aebf8b53c6713abaca38be9bf0a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9f9b9f5a85d3005e4c613b6c2ba20b6d5d388645"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Konstant LLC" and
            (
                pe.signatures[i].serial == "ad:bb:8a:eb:f8:b5:3c:67:13:ab:ac:a3:8b:e9:bf:0a" or
                pe.signatures[i].serial == "00:ad:bb:8a:eb:f8:b5:3c:67:13:ab:ac:a3:8b:e9:bf:0a"
            )
        )
}

rule INDICATOR_KB_CERT_1ffc9825644caf5b1f521780c5c7f42c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4e7e022c7bb6bd90a75674a67f82e839d54a0a5e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ACTIVUS LIMITED" and
            pe.signatures[i].serial == "1f:fc:98:25:64:4c:af:5b:1f:52:17:80:c5:c7:f4:2c"
        )
}

rule INDICATOR_KB_CERT_3112c69d460c781fd649c71e61bfec82 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7ec961d2c69f7686e33f39d497a5e3039e512cf3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KREATURHANDLER BJARNE ANDERSEN ApS" and
            pe.signatures[i].serial == "31:12:c6:9d:46:0c:78:1f:d6:49:c7:1e:61:bf:ec:82"
        )
}

rule INDICATOR_KB_CERT_f64e5b34dc0e4893495d3b9fd9cde4b7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "49373674eb2190c227455c9b5833825fe01f957a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMASoft" and
            pe.signatures[i].serial == "f6:4e:5b:34:dc:0e:48:93:49:5d:3b:9f:d9:cd:e4:b7"
        )
}

rule INDICATOR_KB_CERT_6bec31a0a40d2e834e51ae704e1bf9d3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7a236872302156c58d493b63a1607a09c4f1d0b8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "whatsupfuckers" and
            pe.signatures[i].serial == "6b:ec:31:a0:a4:0d:2e:83:4e:51:ae:70:4e:1b:f9:d3"
        )
}

rule INDICATOR_KB_CERT_9fac361ee3304079 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2168032804def9cdbc1fc1a669377d494832f4ec"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "2021945 Ontario Inc." and
            (
                pe.signatures[i].serial == "9f:ac:36:1e:e3:30:40:79" or
                pe.signatures[i].serial == "00:9f:ac:36:1e:e3:30:40:79"
            )
        )
}

rule INDICATOR_KB_CERT_1895de749994d0db {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "069b9cb52a325a829aba7731ead939bc4ebf3743"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "2021945 Ontario Inc." and
            pe.signatures[i].serial == "18:95:de:74:99:94:d0:db"
        )
}

rule INDICATOR_KB_CERT_28b691272719b1ee {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5dcbc94a2fdcc151afa8c55f24d0d5124d3b6134"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "2021945 Ontario Inc." and
            pe.signatures[i].serial == "28:b6:91:27:27:19:b1:ee"
        )
}

rule INDICATOR_KB_CERT_00e3b80c0932b52a708477939b0d32186f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1d2b5d4f0de1d7ce4abf82fdc58adc43bc28adee"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BISOYETUTU LTD LIMITED" and
            (
                pe.signatures[i].serial == "e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f" or
                pe.signatures[i].serial == "00:e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f"
            )
        )
}

rule INDICATOR_KB_CERT_00c667ffe3a5b0a5ae7cf3a9e41682e91b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6b66ba34ff01e0dab6e68ba244d991578a69c4ad"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and
            (
                pe.signatures[i].serial == "c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b" or
                pe.signatures[i].serial == "00:c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b"
            )
        )
}

rule INDICATOR_KB_CERT_7c1118cbbadc95da3752c46e47a27438 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5b9e273cf11941fd8c6be3f038c4797bbe884268"
        hash1 = "f8da3ee80f71b994d8921f9d902456cbd5187e1bdcd352a81f1d76e0f50ca0b8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Simon Tatham" and
            pe.signatures[i].serial == "7c:11:18:cb:ba:dc:95:da:37:52:c4:6e:47:a2:74:38"
        )
}

rule INDICATOR_KB_CERT_Sagsanlgs {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a6073f35adbdfe26ddc0f647953acc3a9bd33962"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sagsanlgs" and
            pe.signatures[i].serial == "00"
        )
}

/*
rule INDICATOR_KB_CERT_66660552d465b31f429f7527ea6a93bf {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "99ebe773e163542c94817aaac3b93a6704732eee"
        hash1 = "aef73ec2ad7d70e70816e3c0c59e4be96926a7abaae206edcc29db36255e7df3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Symantec Corporation" and
            pe.signatures[i].serial == "66:66:05:52:d4:65:b3:1f:42:9f:75:27:ea:6a:93:bf"
        )
}
*/

rule INDICATOR_KB_CERT_00989a33b72a2aa29e32d0a5e155c53963 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3f53d410d2d959197f4a93d81a898f424941e11f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TAKE CARE SP Z O O" and
            (
                pe.signatures[i].serial == "98:9a:33:b7:2a:2a:a2:9e:32:d0:a5:e1:55:c5:39:63" or
                pe.signatures[i].serial == "00:98:9a:33:b7:2a:2a:a2:9e:32:d0:a5:e1:55:c5:39:63"
            )
        )
}

rule INDICATOR_KB_CERT_00b8f726508cf1d7b7913bf4bbd1e5c19c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0711adcedb225b82dc32c1435ff32d0a1e54911a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TMerkuri LLC" and
            (
                pe.signatures[i].serial == "b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c" or
                pe.signatures[i].serial == "00:b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c"
            )
        )
}

rule INDICATOR_KB_CERT_0aa099e64e214d655801ea38ad876711 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0789b35fd5c2ef8142e6aae3b58fff14e4f13136"
        hash1 = "9f90e6711618a1eab9147f90bdedd606fd975b785915ae37e50e7d2538682579"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Psiphon Inc." and
            pe.signatures[i].serial == "0a:a0:99:e6:4e:21:4d:65:58:01:ea:38:ad:87:67:11"
        )
}

rule INDICATOR_KB_CERT_54cc50d147fa549e3f721c754e4e3a91 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e3143f0df21fced02fe5525b297ed4cd389c66e3"
        hash1 = "85adf569d259dc53c5099fea6e90ff3a614a406b4308ebdf9f40e8bed151f526"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ralink Technology Corporation" and
            pe.signatures[i].serial == "54:cc:50:d1:47:fa:54:9e:3f:72:1c:75:4e:4e:3a:91"
        )
}

rule INDICATOR_KB_CERT_1e508bb2398808bc420a5a1f67ba5d0b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "63a3ca4114aef8d5076ec84ff78d2319d5305e5b"
        hash1 = "7ff82a6621e0dd7c29c2e6bcd63920f9b58bc254df9479618b912a1e788ff18b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WakeNet AB" and
            pe.signatures[i].serial == "1e:50:8b:b2:39:88:08:bc:42:0a:5a:1f:67:ba:5d:0b"
        )
}

rule INDICATOR_KB_CERT_008b3333d32b2c2a1d33b41ba5db9d4d2d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7ecaa9a507a6672144a82d453413591067fc1d27"
        hash1 = "5d5684ccef3ce3b6e92405f73794796e131d3cb1424d757828c3fb62f70f6227"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BOOK CAF\\xC3\\x89" and
            (
                pe.signatures[i].serial == "8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d" or
                pe.signatures[i].serial == "00:8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d"
            )
        )
}

rule INDICATOR_KB_CERT_b548765eebe9468348af40b9891c1e63 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5987703bc4a3c739f92af8fed1747394880e1a39"
        hash1 = "501dee454ba470aa09ceceb4c93ab7e9e913729e47fcc184a2e2d675f8234a58"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OSIRIS Corporation" and
            pe.signatures[i].serial == "b5:48:76:5e:eb:e9:46:83:48:af:40:b9:89:1c:1e:63"
        )
}

rule INDICATOR_KB_CERT_4697c7ddd3e37fe275fdc6961a9093e3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ef24ae3635929c371d1427901082be9f76e58d9a"
        hash1 = "fb3f622cf5557364a0a3abacc3e9acf399b3631bf3630acb8132514c486751e7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xC3\\x89tienne Hill" and
            pe.signatures[i].serial == "46:97:c7:dd:d3:e3:7f:e2:75:fd:c6:96:1a:90:93:e3"
        )
}

rule INDICATOR_KB_CERT_74c94ef697dc9783f845d26dccc1e7fd {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6daa64d7af228de45ded86ad4d1aeaa360295f56"
        hash1 = "45e35c9b095871fbc9b85afff4e79dd36b7812b96a302e1ccc65ce7668667fe6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CIBIKART d.o.o." and
            pe.signatures[i].serial == "74:c9:4e:f6:97:dc:97:83:f8:45:d2:6d:cc:c1:e7:fd"
        )
}

rule INDICATOR_KB_CERT_5dd1cb148a90123dcc13498b54e5a798 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3a7c692345b67c7a2b21a6d94518588c8bbe514c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "33adab6a2ixdac07i4cLb4ac05j6yG2ew95e" and
            pe.signatures[i].serial == "5d:d1:cb:14:8a:90:12:3d:cc:13:49:8b:54:e5:a7:98"
        )
}

rule INDICATOR_KB_CERT_00a758504e7971869d0aec2775fffa03d5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "646bbb3a37cc004bea6efcd48579d1a5776cb157"
        hash1 = "3194e2fb68c007cf2f6deaa1fb07b2cc68292ee87f37dff70ba142377e2ca1fa"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Amcert LLC" and
            (
                pe.signatures[i].serial == "a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5" or
                pe.signatures[i].serial == "00:a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5"
            )
        )
}

rule INDICATOR_KB_CERT_00f13a4f94bf233525 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "974eb056bb7467d54aae25a908ce661dac59c786"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SocketOptionName" and
            (
                pe.signatures[i].serial == "f1:3a:4f:94:bf:23:35:25" or
                pe.signatures[i].serial == "00:f1:3a:4f:94:bf:23:35:25"
            )
        )
}

rule INDICATOR_KB_CERT_119acead668bad57a48b4f42f294f8f0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "11ff68da43f0931e22002f1461136c662e623366"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PB03 TRANSPORT LTD." and
            pe.signatures[i].serial == "11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0"
        )
}

rule INDICATOR_KB_CERT_21144343720267ba42f586105ff279de {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c56f79b4cc3a0e0894cd1e54facdf2db9d8ca62a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Varta Blue Dynamic" and
            pe.signatures[i].serial == "21:14:43:43:72:02:67:ba:42:f5:86:10:5f:f2:79:de"
        )
}

rule INDICATOR_KB_CERT_00a3cb8e964244768969b837ca9981de68 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5617114bc2a584532eba1dd9eb9d23108d1f9ea7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].serial == "a3:cb:8e:96:42:44:76:89:69:b8:37:ca:99:81:de:68" or
            pe.signatures[i].serial == "00:a3:cb:8e:96:42:44:76:89:69:b8:37:ca:99:81:de:68"
        )
}

rule INDICATOR_KB_CERT_00bd96f0b87edca41e777507015b3b2775 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "abfa72d4a78a9e63f97c90bcccb8f46f3c14ac52"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ООО \"СМ\"" and
            (
                pe.signatures[i].serial == "bd:96:f0:b8:7e:dc:a4:1e:77:75:07:01:5b:3b:27:75" or
                pe.signatures[i].serial == "00:bd:96:f0:b8:7e:dc:a4:1e:77:75:07:01:5b:3b:27:75"
            )
        )
}

rule INDICATOR_KB_CERT_00e41537b8dd65670d6eb01954becacf1e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "150ff604efa1e4868ea47c5d48244e57fa4b9196"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Marketing Concept s.r.o." and
            (
                pe.signatures[i].serial == "e4:15:37:b8:dd:65:67:0d:6e:b0:19:54:be:ca:cf:1e" or
                pe.signatures[i].serial == "00:e4:15:37:b8:dd:65:67:0d:6e:b0:19:54:be:ca:cf:1e"
            )
        )
}

rule INDICATOR_KB_CERT_06808c5934da036a1297a936d72e93d4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "efb70718bc00393a01694f255a28e30e9d2142a4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rhaon Entertainment Inc" and
            pe.signatures[i].serial == "06:80:8c:59:34:da:03:6a:12:97:a9:36:d7:2e:93:d4"
        )
}

rule INDICATOR_KB_CERT_97d50c7e3ab45b9a441a37d870484c10 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2e47ceb6593c9fdbd367da8b765090e48f630b33"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SHENZHEN MINIWAN TECHNOLOGY CO. LTD." and
            pe.signatures[i].serial == "97:d5:0c:7e:3a:b4:5b:9a:44:1a:37:d8:70:48:4c:10"
        )
}

rule INDICATOR_KB_CERT_0b2b192657b37632518b08a06e201381 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ea017224c3b209abf53941cc4110e93af7ecc7b1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Atomic Protocol Systems" and
            pe.signatures[i].serial == "0b:2b:19:26:57:b3:76:32:51:8b:08:a0:6e:20:13:81"
        )
}

rule INDICATOR_KB_CERT_00945aaac27e7d6d810c0a542bedd562a4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "de7794505df4aeb1253500617e812f462592e163"
        hash1 = "df3dabd031184b67bab7043baaae17061c21939d725e751c0a6f6b7867d0cf34"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DYNAMX BUSINESS GROUP LTD." and
            (
                pe.signatures[i].serial == "94:5a:aa:c2:7e:7d:6d:81:0c:0a:54:2b:ed:d5:62:a4" or
                pe.signatures[i].serial == "00:94:5a:aa:c2:7e:7d:6d:81:0c:0a:54:2b:ed:d5:62:a4"
            )
        )
}

rule INDICATOR_KB_CERT_6d450cc59acdb4b7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "bd3ac678cabb6465854880dd06b7b6cd231def89"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CancellationTokenSource" and
            pe.signatures[i].serial == "6d:45:0c:c5:9a:cd:b4:b7"
        )
}

rule INDICATOR_KB_CERT_66390fc17786d4a342f0ee89996d6522 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "80e8620ff16598cc1e157a2b7df17d528b03b6e5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Logitech Z-" and
            pe.signatures[i].serial == "66:39:0f:c1:77:86:d4:a3:42:f0:ee:89:99:6d:65:22"
        )
}

rule INDICATOR_KB_CERT_00d1737e5a94d2aff121163df177ed7cf7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ed2e4f72e8cb9b008a28b31de440f024381e4c8d"
        hash1 = "66dfb7c408d734edc2967d50244babae27e4268ea93aa0daa5e6bbace607024c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BedstSammen ApS" and
            (
                pe.signatures[i].serial == "d1:73:7e:5a:94:d2:af:f1:21:16:3d:f1:77:ed:7c:f7" or
                pe.signatures[i].serial == "00:d1:73:7e:5a:94:d2:af:f1:21:16:3d:f1:77:ed:7c:f7"
            )
        )
}

rule INDICATOR_KB_CERT_5aa94583a95d42f1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0b27715d7c78368bca3ac0bb829a7ceb19b3b5c3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UInt32" and
            pe.signatures[i].serial == "5a:a9:45:83:a9:5d:42:f1"
        )
}

rule INDICATOR_KB_CERT_6ce7a0c62f27fa98f78853e1ad11173f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "638dc7cd59f1d634c19e4fc2c41b38ae08a1d2e5"
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0xe011cfd0) and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "D&K ENGINEERING" and
            pe.signatures[i].serial == "6c:e7:a0:c6:2f:27:fa:98:f7:88:53:e1:ad:11:17:3f"
        )
}

rule INDICATOR_KB_CERT_670c3494206b9f0c18714fdcffaaa42f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "59612473a9e23dc770f3a33b1ef83c02e3cfd4b6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ADRIATIK PORT SERVIS, d.o.o." and
            pe.signatures[i].serial == "67:0c:34:94:20:6b:9f:0c:18:71:4f:dc:ff:aa:a4:2f"
        )
}

rule INDICATOR_KB_CERT_5f11c47d3f8c468e5d38279de98078ce {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "29bbee51837dbc00c8e949ff2c0226d4bbb3722c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Atera Networks LTD." and
            pe.signatures[i].serial == "5f:11:c4:7d:3f:8c:46:8e:5d:38:27:9d:e9:80:78:ce"
        )
}

rule INDICATOR_KB_CERT_00bdb99d5ecf8271d48e35f1039c2160ef {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "331f96a1a187723eaa5b72c9d0115c1c57f08b66"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Gavrilov Andrei Alekseevich" and
            (
                pe.signatures[i].serial == "bd:b9:9d:5e:cf:82:71:d4:8e:35:f1:03:9c:21:60:ef" or
                pe.signatures[i].serial == "00:bd:b9:9d:5e:cf:82:71:d4:8e:35:f1:03:9c:21:60:ef"
            )
        )
}

rule INDICATOR_KB_CERT_025020668f51235e9ecfff8cf00da63e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "59f82837fa672a81841d8fa4d3ba290395c10200"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Knassar DK ApS" and
            pe.signatures[i].serial == "02:50:20:66:8f:51:23:5e:9e:cf:ff:8c:f0:0d:a6:3e"
        )
}

rule INDICATOR_KB_CERT_00cfae7e6f538b9f2e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3152fc5298e42de08ed2dec23d8fefcaa531c771"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SequenceDesigner" and
            (
                pe.signatures[i].serial == "cf:ae:7e:6f:53:8b:9f:2e" or
                pe.signatures[i].serial == "00:cf:ae:7e:6f:53:8b:9f:2e"
            )
        )
}

rule INDICATOR_KB_CERT_0bc9b800f480691bd6b60963466b0c75 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8b6c4fc3d54f41ac137795e64477491c93bdf7f1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HasCred ApS" and
            pe.signatures[i].serial == "0b:c9:b8:00:f4:80:69:1b:d6:b6:09:63:46:6b:0c:75"
        )
}

rule INDICATOR_KB_CERT_69ad1e8b5941c93d5017b7c3fdb8e7b6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9b6f3b3cd33ae938fbc5c95b8c9239bac9f9f7bf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Afia Wave Enterprises Oy" and
            pe.signatures[i].serial == "69:ad:1e:8b:59:41:c9:3d:50:17:b7:c3:fd:b8:e7:b6"
        )
}

rule INDICATOR_KB_CERT_072472f2386f4608a0790da2be8a48f7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e2a79e70b7a16a6fc2af7fbdc3d2cbfd3ef66978"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FOXIT SOFTWARE INC." and
            pe.signatures[i].serial == "07:24:72:f2:38:6f:46:08:a0:79:0d:a2:be:8a:48:f7"
        )
}

/*
rule INDICATOR_KB_CERT_24692663ef6c0c0a3b23cfa310c3649b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9ce9a71ccab3b38a74781b975f1c228222cf7d3b"
        hash1 = "c7faae85681abe125b9a81b798daf845c62ddab8014784b6fd1b184b02d5a22b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Akeo Consulting" and
            pe.signatures[i].serial == "24:69:26:63:ef:6c:0c:0a:3b:23:cf:a3:10:c3:64:9b"
        )
}
*/

rule INDICATOR_KB_CERT_00ea734e1dfb6e69ed2bc55e513bf95b5e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5ca53cc5c6dc47838bbba922ad217a468408a9bd"
        hash1 = "293a83bfe2839bfa6d40fa52f5088e43b62791c08343c3f4dade4f1118000392"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Postmarket LLC" and
            (
                pe.signatures[i].serial == "00:ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e" or
                pe.signatures[i].serial == "ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e"
            )
        )
}

rule INDICATOR_KB_CERT_0dfa4f0cff90319951b019a4681ebd2a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b85aacac6afb0bef5b6f1d744cd8c278030e6a3e"
        hash1 = "4eca4e0d3c06e4889917a473229b368bae02f0135f0ac68e937a72fca431ac8a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "deepinstruction O" and
            pe.signatures[i].serial == "0d:fa:4f:0c:ff:90:31:99:51:b0:19:a4:68:1e:bd:2a"
        )
}

rule INDICATOR_KB_CERT_4d03ae6512b85eab4184ca7f4fa2e49c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0215ff94a5c0d97db82e11f87e0dfb4318acac38"
        hash1 = "18bf017bdd74e8e8f5db5a4dd7ec3409021c7b0d2f125f05d728f3b740132015"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lenovo IdeaCentre" and
            pe.signatures[i].serial == "4d:03:ae:65:12:b8:5e:ab:41:84:ca:7f:4f:a2:e4:9c"
        )
}

rule INDICATOR_KB_CERT_333705c20b56e57f60b5eb191eef0d90 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "44f0f77d8b649579fa6f88ae9fa4b4206b90b120"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TASK Holding ApS" and
            pe.signatures[i].serial == "33:37:05:c2:0b:56:e5:7f:60:b5:eb:19:1e:ef:0d:90"
        )
}

rule INDICATOR_KB_CERT_79906faf4fbd75baa10b322356a07f6d {
    meta:
        author = "ditekSHen"
        description = "Detects NetSupport (client) signed executables"
        thumbprint = "f84ec9488bdac5f90db3c474b55e31a8f10a2026"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NetSupport Ltd" and
            pe.signatures[i].serial == "79:90:6f:af:4f:bd:75:ba:a1:0b:32:23:56:a0:7f:6d"
        )
}

rule INDICATOR_KB_CERT_030ba877daf788a0048d04a85b1f6eca {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1f10c5676a742548fb430fbc1965b20146b7325a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Skylum Software USA, Inc." and
            pe.signatures[i].serial == "03:0b:a8:77:da:f7:88:a0:04:8d:04:a8:5b:1f:6e:ca"
        )
}

rule INDICATOR_KB_CERT_00fe83f58d001327fbaafd7bac76ae6818 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c130dd74928da75a42e9d32a1d3f2fd860d81566"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "A. Jensen FLY Fishing ApS" and
            (
                pe.signatures[i].serial == "fe:83:f5:8d:00:13:27:fb:aa:fd:7b:ac:76:ae:68:18" or
                pe.signatures[i].serial == "00:fe:83:f5:8d:00:13:27:fb:aa:fd:7b:ac:76:ae:68:18"
            )
        )
}

rule INDICATOR_KB_CERT_0788260f8541539d97f49ddaa837b166 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "569511fdc5e8dea454e97b005de1af5272d4bd32"
        hash1 = "6ad407d5c7e4574c7452a1a27da532ee9a55bb4074e43aa677703923909169e4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TechSmith Corporation" and
            pe.signatures[i].serial == "07:88:26:0f:85:41:53:9d:97:f4:9d:da:a8:37:b1:66"
        )
}

rule INDICATOR_KB_CERT_0ca5acafb5fdca6f8b5d66d1339a5d85 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ab25053a3f739ddd4505cf5d9d33b5cc50f3ab35"
        hash1 = "a3ab41d9642a5a5aa6aa4fc1e316970e06fa26c6c545dd8ff56f82f41465ec08"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Valve" and
            pe.signatures[i].serial == "0c:a5:ac:af:b5:fd:ca:6f:8b:5d:66:d1:33:9a:5d:85"
        )
}

rule INDICATOR_KB_CERT_387eeb89b8bf626bbf4c7c9f5b998b40 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e94ad249747fd4b88750b2cd6d8d65ad33d3566d"
        hash1 = "004f011b37e4446fa04b76aae537cc00f6588c0705839152ae2d8a837ef2b730"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ULTRA ACADEMY LTD" and
            pe.signatures[i].serial == "38:7e:eb:89:b8:bf:62:6b:bf:4c:7c:9f:5b:99:8b:40"
        )
}

rule INDICATOR_KB_CERT_035b41766660b08aaf121536f0d83d4d {
    meta:
        author = "ditekSHen"
        description = "Detects signed excutable of DiskCryptor open encryption solution that offers encryption of all disk partitions"
        thumbprint = "2022d012c23840314f5eeaa298216bec06035787"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Alexander Lomachevsky" and
            pe.signatures[i].serial == "03:5b:41:76:66:60:b0:8a:af:12:15:36:f0:d8:3d:4d"
        )
}

rule INDICATOR_KB_CERT_1a041db92237c18948109789f627b3cd {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2315cf802aaf96d11f18766315239016e533bf32"
        hash1 = "a0338becbfe808bc7655d8b6c825e2e99b37945e5d8fc43a83aec479d64f422d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Amitotic" and
            pe.signatures[i].serial == "1a:04:1d:b9:22:37:c1:89:48:10:97:89:f6:27:b3:cd"
        )
}

rule INDICATOR_KB_CERT_06df5c318759d6ea9d090bfb2faf1d94 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4418e9a7aab0909fa611985804416b1aaf41e175"
        hash1 = "47dbb2594cd5eb7015ef08b7fb803cd5adc1a1fbe4849dc847c0940f1ccace35"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SpiffyTech Inc." and
            pe.signatures[i].serial == "06:df:5c:31:87:59:d6:ea:9d:09:0b:fb:2f:af:1d:94"
        )
}

// DECAF Ransomware
rule INDICATOR_KB_CERT_330000026551ae1bbd005cbfbd000000000265 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e168609353f30ff2373157b4eb8cd519d07a2bff"
        hash1 = "a471fdf6b137a6035b2a2746703cd696089940698fd533860d34e71cc6586850"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Windows" and
            pe.signatures[i].issuer contains "Microsoft Windows Production PCA 2011" and
            pe.signatures[i].serial == "33:00:00:02:65:51:ae:1b:bd:00:5c:bf:bd:00:00:00:00:02:65" and
            1614796238 <= pe.signatures[i].not_after
        )
}

rule INDICATOR_KB_CERT_309368b122ab63103dddd4ad6321a82c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1370de077e2ba2065478dee8075b16c0e5a5e862"
        hash1 = "b7376049b73feb5bc677a02e4040f2ec7e7302456db9eac35c71072dd95557eb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Systems Accounting Limited" and
            pe.signatures[i].serial == "30:93:68:b1:22:ab:63:10:3d:dd:d4:ad:63:21:a8:2c"
        )
}

rule INDICATOR_KB_CERT_19f613cf951d49814250701037442ee2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint1 = "6feab07fa782fc7fbddde8465815f4d04d79ad97"
        thumbprint2 = "41aaafa56a30badb291e96d31ed15a9343ba7ed3"
        hash1 = "9629cae6d009dadc60e49f5b4a492bd1169d93f17afa76bee27c37be5bca3015"
        hash2 = "3b3281feef6d8e0eda2ab7232bd93f7c747bee143c2dfce15d23a1869bf0eddf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cooler Master" and
            (
                pe.signatures[i].serial == "19:f6:13:cf:95:1d:49:81:42:50:70:10:37:44:2e:e2" or
                pe.signatures[i].serial == "6b:e8:ee:f0:82:a4:f5:96:4c:75:0b:c0:07:24:f6:4a"
            )
        )
}

rule INDICATOR_KB_CERT_2d8cfcf04209dc7f771d8d18e462c35a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a9c61e299634ba01e269239de322fb85e2da006b"
        hash1 = "af27173ed576215bb06dab3a1526992ee1f8bd358a92d63ad0cfbc0325c70acf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AA PLUS INVEST d.o.o." and
            pe.signatures[i].serial == "2d:8c:fc:f0:42:09:dc:7f:77:1d:8d:18:e4:62:c3:5a"
        )
}

rule INDICATOR_KB_CERT_06de439ba2df4dcd8240c211d60cdf5e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2650a1205bd7720381c00bdee5aede0ee333dc13"
        hash1 = "e3bc81a59fc45dfdfcc57b0078437061cb8c3396e1d593fcf187e3cdf0373ed1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microleaves LTD" and
            pe.signatures[i].serial == "06:de:43:9b:a2:df:4d:cd:82:40:c2:11:d6:0c:df:5e"
        )
}

rule INDICATOR_KB_CERT_00f454f2fdc800b3454059d8889bd73d67 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2b560fabc34e0db81dae1443b1c4929eef820266"
        hash1 = "e58b80e4738dc03f5aa82d3a40a6d2ace0d7c7cfd651f1dd10df76d43d8c0eb3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BEAUTY CORP SRL" and
            (
                pe.signatures[i].serial == "f4:54:f2:fd:c8:00:b3:45:40:59:d8:88:9b:d7:3d:67" or
                pe.signatures[i].serial == "00:f4:54:f2:fd:c8:00:b3:45:40:59:d8:88:9b:d7:3d:67"
            )
        )
}

rule INDICATOR_KB_CERT_3afe693728f8406054a613f6736f89e3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "89528e9005a635bcee8da5539e71c5fc4f839f50"
        hash1 = "d98bdf3508763fe0df177ef696f5bf8de7ff7c7dc68bb04a14a95ec28528c3f9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ROB ALDERMAN FITNESS LIMITED" and
            pe.signatures[i].serial == "3a:fe:69:37:28:f8:40:60:54:a6:13:f6:73:6f:89:e3"
        )
}

rule INDICATOR_KB_CERT_0fd7f9cac1e9ce71ac757f93266e3b13 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "af2779ceb127caa6c22232ad359888a0a71ce221"
        hash1 = "7c28b994aeb3a85e37225cc20bae2232f97e23f115c2a409da31f353140c631e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE9\\x9D\\x92\\xE5\\xB2\\x9B\\xE4\\xB8\\x89\\xE5\\x96\\x9C\\xE8\\xB4\\xB8\\xE6\\x98\\x93\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "0f:d7:f9:ca:c1:e9:ce:71:ac:75:7f:93:26:6e:3b:13"
        )
}

rule INDICATOR_KB_CERT_5fbf16a33d26390a15f046c310030cf0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "61f422db86bbc5093b1466a281f13346f8d81792"
        hash1 = "f45e5f160a6de454d1db21b599843637103506545183a30053d03b609f92bbdc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MACHINES SATU MARE SRL" and
            pe.signatures[i].serial == "5f:bf:16:a3:3d:26:39:0a:15:f0:46:c3:10:03:0c:f0"
        )
}

rule INDICATOR_KB_CERT_292eb1133507f42e6f36c5549c189d5e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "48c32548ff651e2aac12716efb448f5583577e35"
        hash1 = "f0b3b36086e58964bf4b9d655568ab5c7f798bd89e7a8581069e65f8189c0b79"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Affairs-case s.r.o." and
            pe.signatures[i].serial == "29:2e:b1:13:35:07:f4:2e:6f:36:c5:54:9c:18:9d:5e"
        )
}

rule INDICATOR_KB_CERT_2aaa455a172f7e3a2dffb5c6b14f9c16 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "23c91b66bd07e56e60724b0064d4fedbdb1c8913"
        hash1 = "7852cf2dfe60b60194dae9b037298ed0a9c84fa1d850f3898751575f4377215f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DREAM VILLAGE s.r.o." and
            pe.signatures[i].serial == "2a:aa:45:5a:17:2f:7e:3a:2d:ff:b5:c6:b1:4f:9c:16"
        )
}

rule INDICATOR_KB_CERT_1ef6392b2993a6f67578299659467ea8 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e87d3e289ccb9f8f9caa53f2aefba102fbf4b231"
        hash1 = "8282e30e3013280878598418b2b274cadc5e00febaa2b93cf25bb438ee6eb032"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALUSEN d. o. o." and
            pe.signatures[i].serial == "1e:f6:39:2b:29:93:a6:f6:75:78:29:96:59:46:7e:a8"
        )
}

rule INDICATOR_KB_CERT_0f007898afcba5f8af8ae65d01803617 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5687481a453414e63e76e1135ed53f4bd0410b05"
        hash1 = "815f1f87e2df79e3078c63b3cb1ffb7d17fd24f6c7092b8bbe1f5f8ceda5df22"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TechnoElek s.r.o." and
            pe.signatures[i].serial == "0f:00:78:98:af:cb:a5:f8:af:8a:e6:5d:01:80:36:17"
        )
}

rule INDICATOR_KB_CERT_00aa1d84779792b57f91fe7a4bde041942 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6c15651791ea8d91909a557eadabe3581b4d1be9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AXIUM NORTHWESTERN HYDRO INC." and
            (
                pe.signatures[i].serial == "aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42" or
                pe.signatures[i].serial == "00:aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42"
            )
        )
}

rule INDICATOR_KB_CERT_0690ee21e99b1cb3b599bba7b9262cdc {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ff9a35ef5865024e49096672ab941b5c120657b9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xiamen Tongbu Networks Ltd." and
            pe.signatures[i].serial == "06:90:ee:21:e9:9b:1c:b3:b5:99:bb:a7:b9:26:2c:dc"
        )
}

rule INDICATOR_KB_CERT_425dc3e0ca8bcdce19d00d87e3f0ba28 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c58bc4370fa01d9a7772fa8c0e7c4c6c99b90561"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Protover LLC" and
            pe.signatures[i].serial == "42:5d:c3:e0:ca:8b:cd:ce:19:d0:0d:87:e3:f0:ba:28"
        )
}

rule INDICATOR_KB_CERT_00881573fc67ff7395dde5bccfbce5b088 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "31b3a3c173c2a2d1086794bfc8d853e25e62fb46"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Trade in Brasil s.r.o." and
            (
                pe.signatures[i].serial == "88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88" or
                pe.signatures[i].serial == "00:88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88"
            )
        )
}

rule INDICATOR_KB_CERT_15c5af15afecf1c900cbab0ca9165629 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "69735ec138c555d9a0d410c450d8bcc7c222e104"
        hash1 = "2ae575f006fc418c72a55ec5fdc26bc821aa3929114ee979b7065bf5072c488f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kompaniya Auttek" and
            pe.signatures[i].serial == "15:c5:af:15:af:ec:f1:c9:00:cb:ab:0c:a9:16:56:29"
        )
}

rule INDICATOR_KB_CERT_12705fb66bc22c68372a1c4e5fa662e2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "288959bd1e8dd12f773e9601dc21c57678769909"
        hash1 = "151b1495d6d1c68e32cdba36d6d3e1d40c8c0d3c12e9e5bd566f1ee742b81b4e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APRIL BROTHERS LTD" and
            pe.signatures[i].serial == "12:70:5f:b6:6b:c2:2c:68:37:2a:1c:4e:5f:a6:62:e2"
        )
}

rule INDICATOR_KB_CERT_205483936f360924e8d2a4eb6d3a9f31 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "430dbeff2f6df708b03354d5d07e78400cfed8e9"
        hash1 = "e58b9bbb7bcdf3e901453b7b9c9e514fed1e53565e3280353dccc77cde26a98e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SATURN CONSULTANCY LTD" and
            pe.signatures[i].serial == "20:54:83:93:6f:36:09:24:e8:d2:a4:eb:6d:3a:9f:31"
        )
}

rule INDICATOR_KB_CERT_06bcb74291d96096577bdb1e165dce85 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d1bde6303266977f7540221543d3f2625da24ac4"
        hash1 = "074cef597dc028b08dc2fe927ea60f09cfd5e19f928f2e4071860b9a159b365d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Revo Security SRL" and
            pe.signatures[i].serial == "06:bc:b7:42:91:d9:60:96:57:7b:db:1e:16:5d:ce:85"
        )
}