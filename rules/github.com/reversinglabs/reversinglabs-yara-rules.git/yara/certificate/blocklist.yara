/*

 YARA doesn't perform complete digital certificate chain validation.

 This can cause unwanted matches for:
    a) Files that are signed with non-verified, self-issued, certificates
    b) Files that fail integrity validation due to checksum mismatch
    c) Files that have extra data appended after the certificate

 It's also worth mentioning that the timestamp value in the condition is only
 informative, since YARA doesn't extract timestamping certificate information.
 This information could be used in combination with other tools to reduce
 potential false positives.

 ReversingLabs recommends using Titanium platform for best results with certificate-based classifications.

 References on importance of certificate verification:
    https://blog.reversinglabs.com/blog/tampering-with-signed-objects-without-breaking-the-integrity-seal
    https://blog.reversinglabs.com/blog/breaking-the-windows-authenticode-security-model
    https://blog.reversinglabs.com/blog/breaking-uefi-firmware-authenticode-security-model
    https://blog.reversinglabs.com/blog/breaking-the-linux-authenticode-security-model

*/

import "pe"

rule cert_blocklist_05e2e6a4cd09ea54d665b075fe22A256 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "*.google.com" and
            pe.signatures[i].serial == "05:e2:e6:a4:cd:09:ea:54:d6:65:b0:75:fe:22:a2:56" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_77019a082385e4b73f569569c9f87bb8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AND LLC" and
            pe.signatures[i].serial == "77:01:9a:08:23:85:e4:b7:3f:56:95:69:c9:f8:7b:b8" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4f2ef29ca5f96e5777b82c62f34fd3a6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bit9, Inc" and
            pe.signatures[i].serial == "4f:2e:f2:9c:a5:f9:6e:57:77:b8:2c:62:f3:4f:d3:a6" and
            1342051200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7cc1db2ad0a290a4bfe7a5f336d6800c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bit9, Inc" and
            pe.signatures[i].serial == "7c:c1:db:2a:d0:a2:90:a4:bf:e7:a5:f3:36:d6:80:0c" and
            1342051200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_13c8351aece71c731158980f575f4133 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Opera Software ASA" and
            pe.signatures[i].serial == "13:c8:35:1a:ec:e7:1c:73:11:58:98:0f:57:5f:41:33" and
            1371513600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4531954f6265304055f66ce4f624f95b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IDAutomation.com" and
            pe.signatures[i].serial == "45:31:95:4f:62:65:30:40:55:f6:6c:e4:f6:24:f9:5b" and
            1384819199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0e808f231515bc519eea1a73cdf3266f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Careto malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TecSystem Ltd." and
            pe.signatures[i].serial == "0e:80:8f:23:15:15:bc:51:9e:ea:1a:73:cd:f3:26:6f" and
            1468799999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_36be4ad457f062fa77d87595b8ccc8cf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Careto malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TecSystem Ltd." and
            pe.signatures[i].serial == "36:be:4a:d4:57:f0:62:fa:77:d8:75:95:b8:cc:c8:cf" and
            1372377599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_75a38507bf403b152125b8f5ce1b97ad {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Zeus malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "isonet ag" and
            pe.signatures[i].serial == "75:a3:85:07:bf:40:3b:15:21:25:b8:f5:ce:1b:97:ad" and
            1395359999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4effa8b216e24b16202940c1bc2fa8a5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Henan Maijiamai Technology Co., Ltd." and
            pe.signatures[i].serial == "4e:ff:a8:b2:16:e2:4b:16:20:29:40:c1:bc:2f:a8:a5" and
            1404691199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_57d7153a89bbf4729be87f3c927043aa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, zhenganjun" and
            pe.signatures[i].serial == "57:d7:15:3a:89:bb:f4:72:9b:e8:7f:3c:92:70:43:aa" and
            1469059200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_028e1deccf93d38ecf396118dfe908b4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fortuna Games Co., Ltd." and
            pe.signatures[i].serial == "02:8e:1d:ec:cf:93:d3:8e:cf:39:61:18:df:e9:08:b4" and
            1392163199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_40575df73eaa1b6140c7ef62c08bf216 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dali Feifang Tech Co.,LTD." and
            pe.signatures[i].serial == "40:57:5d:f7:3e:aa:1b:61:40:c7:ef:62:c0:8b:f2:16" and
            1394063999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_049ce8c47f1f0e650cb086f0cfa7ca53 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Select'Assistance Pro" and
            pe.signatures[i].serial == "04:9c:e8:c4:7f:1f:0e:65:0c:b0:86:f0:cf:a7:ca:53" and
            1393804799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_29f42680e653cf8fafd0e935553f7e86 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Wemade Entertainment co.,Ltd" and
            pe.signatures[i].serial == "29:f4:26:80:e6:53:cf:8f:af:d0:e9:35:55:3f:7e:86" and
            1390175999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c15 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "William Richard John" and
            pe.signatures[i].serial == "0c:15" and
            1387324799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c0f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dmitry Vasilev" and
            pe.signatures[i].serial == "0c:0f" and
            1386719999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06a164ec5978497741ee6cec9966871b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JOHN WILLIAM RICHARD" and
            pe.signatures[i].serial == "06:a1:64:ec:59:78:49:77:41:ee:6c:ec:99:66:87:1b" and
            1385596799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1121ed568764e75be35574448feadefcd3bc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FRINORTE COMERCIO DE PECAS E SERVICOS LTDA - ME" and
            pe.signatures[i].serial == "11:21:ed:56:87:64:e7:5b:e3:55:74:44:8f:ea:de:fc:d3:bc" and
            1385337599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6ed2450ceac0f72e73fda1727e66e654 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hohhot Handing Trade and Business Co., Ltd." and
            pe.signatures[i].serial == "6e:d2:45:0c:ea:c0:f7:2e:73:fd:a1:72:7e:66:e6:54" and
            1376092799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_32665079c5a5854a6833623ca77ff5ac {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ohanae" and
            pe.signatures[i].serial == "32:66:50:79:c5:a5:85:4a:68:33:62:3c:a7:7f:f5:ac" and
            1381967999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_01a90094c83412c00cf98dd2eb0d7042 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FreeVox SA" and
            pe.signatures[i].serial == "01:a9:00:94:c8:34:12:c0:0c:f9:8d:d2:eb:0d:70:42" and
            1376956799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_55efe24b9674855baf16e67716479c71 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "S2BVISIO BELGIQUE SA" and
            pe.signatures[i].serial == "55:ef:e2:4b:96:74:85:5b:af:16:e6:77:16:47:9c:71" and
            1374451199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_094bf19d509d3074913995160b195b6c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Porral Twinware S.L.L." and
            pe.signatures[i].serial == "09:4b:f1:9d:50:9d:30:74:91:39:95:16:0b:19:5b:6c" and
            1373241599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a77cf3ba49b64e6cbe5fb4a6a6aacc6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "I.ST.SAN. Srl" and
            pe.signatures[i].serial == "0a:77:cf:3b:a4:9b:64:e6:cb:e5:fb:4a:6a:6a:ac:c6" and
            1371081599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1f4c22da1107d20c1eda04569d58e573 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PlanView, Inc." and
            pe.signatures[i].serial == "1f:4c:22:da:11:07:d2:0c:1e:da:04:56:9d:58:e5:73" and
            1366156799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4fe68d48634893d18de040d8f1c289d2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xinghua Yile Network Tech Co.,Ltd." and
            pe.signatures[i].serial == "4f:e6:8d:48:63:48:93:d1:8d:e0:40:d8:f1:c2:89:d2" and
            1371081600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6767def972d6ea702d8c8a53af1832d3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Guangzhou typical corner Network Technology Co., Ltd." and
            pe.signatures[i].serial == "67:67:de:f9:72:d6:ea:70:2d:8c:8a:53:af:18:32:d3" and
            1361750400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06477e3425f1448995ced539789e6842 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Karim Lammali" and
            pe.signatures[i].serial == "06:47:7e:34:25:f1:44:89:95:ce:d5:39:78:9e:68:42" and
            1334275199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0450a7c1c36951da09c8ad0e7f716ff2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PS Partnership" and
            pe.signatures[i].serial == "04:50:a7:c1:c3:69:51:da:09:c8:ad:0e:7f:71:6f:f2" and
            1362182399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0f9fbdab9b39645cf3211f87abb5ddb7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "The Motivo Group, Inc." and
            pe.signatures[i].serial == "0f:9f:bd:ab:9b:39:64:5c:f3:21:1f:87:ab:b5:dd:b7" and
            1361318399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4211d2e4f0e87127319302c55b85bcf2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "yinsheng xie" and
            pe.signatures[i].serial == "42:11:d2:e4:f0:e8:71:27:31:93:02:c5:5b:85:bc:f2" and
            1360713599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07b44cdbfffb78de05f4261672a67312 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Buster Paper Comercial Ltda" and
            pe.signatures[i].serial == "07:b4:4c:db:ff:fb:78:de:05:f4:26:16:72:a6:73:12" and
            1359503999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4f8b9a1ba5e60c754dbb40ddee7905e2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NOX Entertainment Co., Ltd" and
            pe.signatures[i].serial == "4f:8b:9a:1b:a5:e6:0c:75:4d:bb:40:dd:ee:79:05:e2" and
            1348617599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a389b95ee736dd13bc0ed743fd74d2f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BUSTER ASSISTENCIA TECNICA ELETRONICA LTDA - ME" and
            pe.signatures[i].serial == "0a:38:9b:95:ee:73:6d:d1:3b:c0:ed:74:3f:d7:4d:2f" and
            1351814399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1a3faaeb3a8b93b2394fec36345996e6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "salvatore macchiarella" and
            pe.signatures[i].serial == "1a:3f:aa:eb:3a:8b:93:b2:39:4f:ec:36:34:59:96:e6" and
            1468454400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1a35acce5b0c77206b1c3dc2a6a2417c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "cd ingegneri associati srl" and
            pe.signatures[i].serial == "1a:35:ac:ce:5b:0c:77:20:6b:1c:3d:c2:a6:a2:41:7c" and
            1166054399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6eb40ea11eaac847b050de9b59e25bdc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "My Free Internet Update" and
            pe.signatures[i].serial == "6e:b4:0e:a1:1e:aa:c8:47:b0:50:de:9b:59:e2:5b:dc" and
            1062201599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6724340ddbc7252f7fb714b812a5c04d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "YNK JAPAN Inc" and
            pe.signatures[i].serial == "67:24:34:0d:db:c7:25:2f:7f:b7:14:b8:12:a5:c0:4d" and
            1306195199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0813ee9b7b9d7c46001d6bc8784df1dd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Les Garcons s'habillent" and
            pe.signatures[i].serial == "08:13:ee:9b:7b:9d:7c:46:00:1d:6b:c8:78:4d:f1:dd" and
            1334707199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_530591c61b5e1212f659138b7cea0a97 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\x97\\xA5\\xE7\\x85\\xA7\\xE5\\xB3\\xB0\\xE5\\xB7\\x9D\\xE5\\x9B\\xBD\\xE9\\x99\\x85\\xE7\\x9F\\xBF\\xE4\\xB8\\x9A\\xE8\\xB4\\xB8\\xE6\\x98\\x93\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "53:05:91:c6:1b:5e:12:12:f6:59:13:8b:7c:ea:0a:97" and
            1403654399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07270ff9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Cyber CA" and
            pe.signatures[i].serial == "07:27:0f:f9" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0727100d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Cyber CA" and
            pe.signatures[i].serial == "07:27:10:0d" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07271003 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Cyber CA" and
            pe.signatures[i].serial == "07:27:10:03" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_013134bf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar PKIoverheid CA Organisatie - G2" and
            pe.signatures[i].serial == "01:31:34:bf" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_01314476 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar PKIoverheid CA Overheid" and
            pe.signatures[i].serial == "01:31:44:76" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_013169b0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar PKIoverheid CA Overheid en Bedrijven" and
            pe.signatures[i].serial == "01:31:69:b0" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c76da9c910c4e2c9efe15d058933c4c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Root CA" and
            pe.signatures[i].serial == "0c:76:da:9c:91:0c:4e:2c:9e:fe:15:d0:58:93:3c:4c" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_469c2caf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Root CA" and
            pe.signatures[i].serial == "46:9c:2c:af" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_469c3cc9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Root CA" and
            pe.signatures[i].serial == "46:9c:3c:c9" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a82bd1e144e8814d75b1a5527bebf3e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Root CA G2" and
            pe.signatures[i].serial == "0a:82:bd:1e:14:4e:88:14:d7:5b:1a:55:27:be:bf:3e" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_469c2cb0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Services 1024 CA" and
            pe.signatures[i].serial == "46:9c:2c:b0" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4c0e636a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digisign Server ID - (Enrich)" and
            pe.signatures[i].serial == "4c:0e:63:6a" and
            1320191999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_072714a9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digisign Server ID (Enrich)" and
            pe.signatures[i].serial == "07:27:14:a9" and
            1320191999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_00d8f35f4eb7872b2dab0692e315382fb0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "global trustee" and (
                pe.signatures[i].serial == "00:d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0" or
                pe.signatures[i].serial == "d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0"
            ) and
            1300060800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_750e40ff97f047edf556c7084eb1abfd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Corporation" and
            pe.signatures[i].serial == "75:0e:40:ff:97:f0:47:ed:f5:56:c7:08:4e:b1:ab:fd" and
            980899199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1b5190f73724399c9254cd424637996a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Corporation" and
            pe.signatures[i].serial == "1b:51:90:f7:37:24:39:9c:92:54:cd:42:46:37:99:6a" and
            980812799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_00ebaa11d62e2481081820 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Enforced Licensing Intermediate PCA" and (
                pe.signatures[i].serial == "00:eb:aa:11:d6:2e:24:81:08:18:20" or
                pe.signatures[i].serial == "eb:aa:11:d6:2e:24:81:08:18:20"
            )
        )
}

rule cert_blocklist_3aab11dee52f1b19d056 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Enforced Licensing Intermediate PCA" and
            pe.signatures[i].serial == "3a:ab:11:de:e5:2f:1b:19:d0:56"
        )
}

rule cert_blocklist_6102b01900000000002f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Enforced Licensing Registration Authority CA (SHA1)" and
            pe.signatures[i].serial == "61:02:b0:19:00:00:00:00:00:2f"
        )
}

rule cert_blocklist_01e2b4f759811c64379fca0be76d2dce {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sony Pictures Entertainment Inc." and
            pe.signatures[i].serial == "01:e2:b4:f7:59:81:1c:64:37:9f:ca:0b:e7:6d:2d:ce" and
            1417651200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03e5a010b05c9287f823c2585f547b80 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MOCOMSYS INC" and
            pe.signatures[i].serial == "03:e5:a0:10:b0:5c:92:87:f8:23:c2:58:5f:54:7b:80" and
            1385423999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fe7df6c4b9a33b83d04e23e98a77cce {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PIXELPLUS CO., LTD." and
            pe.signatures[i].serial == "0f:e7:df:6c:4b:9a:33:b8:3d:04:e2:3e:98:a7:7c:ce" and
            1396310399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_065569a3e261409128a40affa90d6d10 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Police Mutual Aid Association" and
            pe.signatures[i].serial == "06:55:69:a3:e2:61:40:91:28:a4:0a:ff:a9:0d:6d:10" and
            1381795199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0979616733e062c544df0abd315e3b92 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jessica Karam" and
            pe.signatures[i].serial == "09:79:61:67:33:e0:62:c5:44:df:0a:bd:31:5e:3b:92" and
            1408319999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7d3250b27e0547c77307030491b42802 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Banco do Brasil S.A." and
            pe.signatures[i].serial == "7d:32:50:b2:7e:05:47:c7:73:07:03:04:91:b4:28:02" and
            1412207999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_00d1836bd37c331a67 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MINDSTORM LLC" and (
                pe.signatures[i].serial == "00:d1:83:6b:d3:7c:33:1a:67" or
                pe.signatures[i].serial == "d1:83:6b:d3:7c:33:1a:67"
            ) and
            1422835199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2ca028d1a4de0eb743135edecf74d7af {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "2c:a0:28:d1:a4:de:0e:b7:43:13:5e:de:cf:74:d7:af" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_dbb14dcf973eada14ece7ea79c895c11 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "db:b1:4d:cf:97:3e:ad:a1:4e:ce:7e:a7:9c:89:5c:11" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f8c2239de3977b8d4a3dcbedc9031a51 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "f8:c2:23:9d:e3:97:7b:8d:4a:3d:cb:ed:c9:03:1a:51" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_caad8222705d3fb3430e114a31c8c6a4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "ca:ad:82:22:70:5d:3f:b3:43:0e:11:4a:31:c8:c6:a4" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b191812516e6618d49e6ccf5e63dc343 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "b1:91:81:25:16:e6:61:8d:49:e6:cc:f5:e6:3d:c3:43" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4ba7fb8ee1deff8f4a1525e1e0580057 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "4b:a7:fb:8e:e1:de:ff:8f:4a:15:25:e1:e0:58:00:57" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2df9f7eb6cdc5ca243b33122e3941e25 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "2d:f9:f7:eb:6c:dc:5c:a2:43:b3:31:22:e3:94:1e:25" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_58a541d50f9e2fab4380c6a2ed433b82 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "58:a5:41:d5:0f:9e:2f:ab:43:80:c6:a2:ed:43:3b:82" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5f273626859ae4bc4becbbeb71e2ab2d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "5f:27:36:26:85:9a:e4:bc:4b:ec:bb:eb:71:e2:ab:2d" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b1ad46ce4db160b348c24f66c9663178 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "b1:ad:46:ce:4d:b1:60:b3:48:c2:4f:66:c9:66:31:78" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_256541e204619033f8b09f9eb7c88ef8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HON HAI PRECISION INDUSTRY CO. LTD." and
            pe.signatures[i].serial == "25:65:41:e2:04:61:90:33:f8:b0:9f:9e:b7:c8:8e:f8" and
            1424303999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_00e8cc18cf100b6b27443ef26319398734 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Syngenta" and (
                pe.signatures[i].serial == "00:e8:cc:18:cf:10:0b:6b:27:44:3e:f2:63:19:39:87:34" or
                pe.signatures[i].serial == "e8:cc:18:cf:10:0b:6b:27:44:3e:f2:63:19:39:87:34"
            ) and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_62af28a7657ba8ab10fa8e2d47250c69 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AFINA Fintek" and
            pe.signatures[i].serial == "62:af:28:a7:65:7b:a8:ab:10:fa:8e:2d:47:25:0c:69" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04c8eca7243208a110dea926c7ad89ce {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, SINGH ADITYA" and
            pe.signatures[i].serial == "04:c8:ec:a7:24:32:08:a1:10:de:a9:26:c7:ad:89:ce" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_157c3a4a6bcf35cf8453e6b6c0072e1d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Favorite-III" and
            pe.signatures[i].serial == "15:7c:3a:4a:6b:cf:35:cf:84:53:e6:b6:c0:07:2e:1d" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04422f12037bc2032521dbb6ae02ea0e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, Muhammad Lee" and
            pe.signatures[i].serial == "04:42:2f:12:03:7b:c2:03:25:21:db:b6:ae:02:ea:0e" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_65eae6c98111dc40bf4f962bf27227f2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, BHARATH KUCHANGI" and
            pe.signatures[i].serial == "65:ea:e6:c9:81:11:dc:40:bf:4f:96:2b:f2:72:27:f2" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_12d5a4b29fe6156d4195fba55ae0d9a9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, Marc Chapon" and
            pe.signatures[i].serial == "12:d5:a4:b2:9f:e6:15:6d:41:95:fb:a5:5a:e0:d9:a9" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0087d60d1e2b9374eb7a735dce4bbdae56 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMO-K Limited Liability Company" and (
                pe.signatures[i].serial == "00:87:d6:0d:1e:2b:93:74:eb:7a:73:5d:ce:4b:bd:ae:56" or
                pe.signatures[i].serial == "87:d6:0d:1e:2b:93:74:eb:7a:73:5d:ce:4b:bd:ae:56"
            ) and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0860c8a7ed18c3f030a32722fd2b220c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, Tony Yeh" and
            pe.signatures[i].serial == "08:60:c8:a7:ed:18:c3:f0:30:a3:27:22:fd:2b:22:0c" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2fdadd0740572270203f8138692c4a83 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, William Zoltan" and
            pe.signatures[i].serial == "2f:da:dd:07:40:57:22:70:20:3f:81:38:69:2c:4a:83" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4fc13d6220c629043a26f81b1cad72d8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, meicun ge" and
            pe.signatures[i].serial == "4f:c1:3d:62:20:c6:29:04:3a:26:f8:1b:1c:ad:72:d8" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3457a918c6d3701b2eaca6a92474a7cc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KONSALTING PLUS OOO" and
            pe.signatures[i].serial == "34:57:a9:18:c6:d3:70:1b:2e:ac:a6:a9:24:74:a7:cc" and
            1432252799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_621ed8265b0ad872d9f4b4ed6d560513 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fan Li" and
            pe.signatures[i].serial == "62:1e:d8:26:5b:0a:d8:72:d9:f4:b4:ed:6d:56:05:13" and
            1413183357 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_56e22b992b4c7f1afeac1d63b492bf54 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, Hetem Ramadani" and
            pe.signatures[i].serial == "56:e2:2b:99:2b:4c:7f:1a:fe:ac:1d:63:b4:92:bf:54" and
            1435622399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3bc3bae4118d46f3fdd9beeeab749fee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\x9D\\x8E\\xE9\\x9B\\xAA\\xE6\\xA2\\x85" and
            pe.signatures[i].serial == "3b:c3:ba:e4:11:8d:46:f3:fd:d9:be:ee:ab:74:9f:ee" and
            1442275199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0f0449f7691e5b4c8e74e71cae822179 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SBO INVEST" and
            pe.signatures[i].serial == "0f:04:49:f7:69:1e:5b:4c:8e:74:e7:1c:ae:82:21:79" and
            1432079999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_43db4448d870d7bdc275f36a01fba36f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3-T TOV" and
            pe.signatures[i].serial == "43:db:44:48:d8:70:d7:bd:c2:75:f3:6a:01:fb:a3:6f" and
            1436227199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2880a7f7ff2d334aa08744a8754fab2c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Garena Online Pte Ltd" and
            pe.signatures[i].serial == "28:80:a7:f7:ff:2d:33:4a:a0:87:44:a8:75:4f:ab:2c" and
            1393891199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0492f5c18e26fa0cd7e15067674aff1c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ghada Saffarini" and
            pe.signatures[i].serial == "04:92:f5:c1:8e:26:fa:0c:d7:e1:50:67:67:4a:ff:1c" and
            1445990399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6aa668cd6a9de1fdd476ea8225326937 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BSCP LIMITED" and
            pe.signatures[i].serial == "6a:a6:68:cd:6a:9d:e1:fd:d4:76:ea:82:25:32:69:37" and
            1441583999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1cb06dccb482255728671ea12ac41620 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fangzhen Li" and
            pe.signatures[i].serial == "1c:b0:6d:cc:b4:82:25:57:28:67:1e:a1:2a:c4:16:20" and
            1445126399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_370c2467c41d6019bbecd72e00c5d73d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UNINFO SISTEMAS LTDA ME" and
            pe.signatures[i].serial == "37:0c:24:67:c4:1d:60:19:bb:ec:d7:2e:00:c5:d7:3d" and
            1445299199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5067339614c5cc219c489d40420f3bf9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "D-LINK CORPORATION" and
            pe.signatures[i].serial == "50:67:33:96:14:c5:cc:21:9c:48:9d:40:42:0f:3b:f9" and
            1441238400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6e32531ae83992f0573120a5e78de271 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3 AM CHP" and
            pe.signatures[i].serial == "6e:32:53:1a:e8:39:92:f0:57:31:20:a5:e7:8d:e2:71" and
            1451606399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6967a89bcf6efef160aaeebbff376c0a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Chang Yucheng" and
            pe.signatures[i].serial == "69:67:a8:9b:cf:6e:fe:f1:60:aa:ee:bb:ff:37:6c:0a" and
            1451174399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7473d95405d2b0b3a8f28785ce6e74ca {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dmitrij Emelyanov" and
            pe.signatures[i].serial == "74:73:d9:54:05:d2:b0:b3:a8:f2:87:85:ce:6e:74:ca" and
            1453939199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04f380f97579f1702a85e0169bbdfd78 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GRANIFLOR" and
            pe.signatures[i].serial == "04:f3:80:f9:75:79:f1:70:2a:85:e0:16:9b:bd:fd:78" and
            1454889599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04d6b8cc6dce353fcf3ae8a532be7255 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MADERA" and
            pe.signatures[i].serial == "04:d6:b8:cc:6d:ce:35:3f:cf:3a:e8:a5:32:be:72:55" and
            1451692799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_191322a00200f793 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PRABHAKAR NARAYAN" and
            pe.signatures[i].serial == "19:13:22:a0:02:00:f7:93" and
            1442966399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_451c9d0b413e6e8df175 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PRASAD UPENDRA" and
            pe.signatures[i].serial == "45:1c:9d:0b:41:3e:6e:8d:f1:75" and
            1442275199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03943858218f35adb7073a6027555621 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RuN APps FOrEver lld" and
            pe.signatures[i].serial == "03:94:38:58:21:8f:35:ad:b7:07:3a:60:27:55:56:21" and
            1480550399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_09813ee7318452c28a1f6426d1cee12d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Saly Younes" and
            pe.signatures[i].serial == "09:81:3e:e7:31:84:52:c2:8a:1f:64:26:d1:ce:e1:2d" and
            1455667199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_476bf24a4b1e9f4bc2a61b152115e1fe {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Wemade Entertainment co.,Ltd" and
            pe.signatures[i].serial == "47:6b:f2:4a:4b:1e:9f:4b:c2:a6:1b:15:21:15:e1:fe" and
            1414454399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7bd55818c5971b63dc45cf57cbeb950b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "XL Games Co.,Ltd." and
            pe.signatures[i].serial == "7b:d5:58:18:c5:97:1b:63:dc:45:cf:57:cb:eb:95:0b" and
            1371513599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4c0b2e9d2ef909d15270d4dd7fa5a4a5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fuqing Dawu Technology Co.,Ltd." and
            pe.signatures[i].serial == "4c:0b:2e:9d:2e:f9:09:d1:52:70:d4:dd:7f:a5:a4:a5" and
            1372118399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5e3d76dc7e273e2f313fc0775847a2a2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula and Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NexG" and
            pe.signatures[i].serial == "5e:3d:76:dc:7e:27:3e:2f:31:3f:c0:77:58:47:a2:a2" and
            1372723199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_47d5d5372bcb1562b4c9f4c2bdf13587 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DTOPTOOLZ Co.,Ltd." and
            pe.signatures[i].serial == "47:d5:d5:37:2b:cb:15:62:b4:c9:f4:c2:bd:f1:35:87" and
            1400803199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3ac10e68f1ce519e84ddcd28b11fa542 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "U-Tech IT service" and
            pe.signatures[i].serial == "3a:c1:0e:68:f1:ce:51:9e:84:dd:cd:28:b1:1f:a5:42" and
            1420156799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_31062e483e0106b18c982f0053185c36 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MICRO DIGITAL INC." and
            pe.signatures[i].serial == "31:06:2e:48:3e:01:06:b1:8c:98:2f:00:53:18:5c:36" and
            1332287999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_20d0ee42fc901e6b3a8fefe8c1e6087a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SJ SYSTEM" and
            pe.signatures[i].serial == "20:d0:ee:42:fc:90:1e:6b:3a:8f:ef:e8:c1:e6:08:7a" and
            1391299199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_127251b32b9a50bd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing OSX DokSpy backdoor."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Developer ID Application: Edouard Roulet (W7J9LRHXTG)" and
            pe.signatures[i].serial == "12:72:51:b3:2b:9a:50:bd" and
            1493769599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_48cad4e6966e22d6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing OSX DokSpy backdoor."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Developer ID Application: Seven Muller (FUP9692NN6)" and
            pe.signatures[i].serial == "48:ca:d4:e6:96:6e:22:d6" and
            1492732799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5e15205f180442cc6c3c0f03e1a33d9f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ziber Ltd" and
            pe.signatures[i].serial == "5e:15:20:5f:18:04:42:cc:6c:3c:0f:03:e1:a3:3d:9f" and
            1498607999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4c8e3b1613f73542f7106f272094eb23 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ADD Audit" and
            pe.signatures[i].serial == "4c:8e:3b:16:13:f7:35:42:f7:10:6f:27:20:94:eb:23" and
            1472687999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2ce2bd0ad3cfde9ea73eec7ca30400da {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Media Lid" and
            pe.signatures[i].serial == "2c:e2:bd:0a:d3:cf:de:9e:a7:3e:ec:7c:a3:04:00:da" and
            1493337599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fbc30db127a536c34d7a0fa81b48193 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Megabit, OOO" and
            pe.signatures[i].serial == "0f:bc:30:db:12:7a:53:6c:34:d7:a0:fa:81:b4:81:93" and
            1466121599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08448bd6ee9105ae31228ea5fe496f63 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Raffaele Carnacina" and
            pe.signatures[i].serial == "08:44:8b:d6:ee:91:05:ae:31:22:8e:a5:fe:49:6f:63" and
            1445212799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_02f17566ef568dc06c9a379ea2f4faea {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VALERIANO BEDESCHI" and
            pe.signatures[i].serial == "02:f1:75:66:ef:56:8d:c0:6c:9a:37:9e:a2:f4:fa:ea" and
            1441324799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7d824ba1f7f730319c50d64c9a7ed507 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "joaweb" and
            pe.signatures[i].serial == "7d:82:4b:a1:f7:f7:30:31:9c:50:d6:4c:9a:7e:d5:07" and
            1238025599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_77a64759f12766e363d779998c71bdc9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Gigabit Times Technology Co., Ltd" and
            pe.signatures[i].serial == "77:a6:47:59:f1:27:66:e3:63:d7:79:99:8c:71:bd:c9" and
            1301011199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0b0d17ec1449b4b2d38fcb0f20fbcd3a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WEBPIC DESENVOLVIMENTO DE SOFTWARE LTDA" and
            pe.signatures[i].serial == "0b:0d:17:ec:14:49:b4:b2:d3:8f:cb:0f:20:fb:cd:3a" and
            1394150399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fe9404dc73cf1c2ba1450b8398305557 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x8E\\xA6\\xE9\\x97\\xA8\\xE7\\xBF\\x94\\xE9\\x80\\x9A\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE5\\x88\\x86\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:fe:94:04:dc:73:cf:1c:2b:a1:45:0b:83:98:30:55:57" or
                pe.signatures[i].serial == "fe:94:04:dc:73:cf:1c:2b:a1:45:0b:83:98:30:55:57"
            ) and
            1287360000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1cb2d523a6bf7a066642c578de1c9be4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shenzhen Hua\\xE2\\x80\\x99nan Xingfa Electronic Equipment Firm" and
            pe.signatures[i].serial == "1c:b2:d5:23:a6:bf:7a:06:66:42:c5:78:de:1c:9b:e4" and
            1400889599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3a6ccabb1c62f3be3eb03869fa43dc4a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\xB8\\xB8\\xE5\\xB7\\x9E\\xE9\\xAA\\x8F\\xE6\\x99\\xAF\\xE9\\x80\\x9A\\xE8\\x81\\x94\\xE6\\x95\\xB0\\xE5\\xAD\\x97\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "3a:6c:ca:bb:1c:62:f3:be:3e:b0:38:69:fa:43:dc:4a" and
            1259798399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_864196f01971dbec7002b48642a7013a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WLE DESENVOLVIMENTO DE SOFTWARE E ASSESSORIA LTDA EPP" and (
                pe.signatures[i].serial == "00:86:41:96:f0:19:71:db:ec:70:02:b4:86:42:a7:01:3a" or
                pe.signatures[i].serial == "86:41:96:f0:19:71:db:ec:70:02:b4:86:42:a7:01:3a"
            ) and
            1384300799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4fda1e121b61adeca936a6aebe079303 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Laizhou wanlei stone Co., LTD" and
            pe.signatures[i].serial == "4f:da:1e:12:1b:61:ad:ec:a9:36:a6:ae:be:07:93:03" and
            1310687999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03866deb183abfbf4ff458d4de7bd73a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE9\\x87\\x8D\\xE5\\xBA\\x86\\xE8\\xAF\\x9D\\xE8\\xAF\\xAD\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "03:86:6d:eb:18:3a:bf:bf:4f:f4:58:d4:de:7b:d7:3a" and
            1371772799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1be41b34127ca9e6270830d2070db426 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE8\\x80\\x98\\xE5\\x8D\\x87\\xE5\\xA4\\xA9\\xE4\\xB8\\x8B\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "1b:e4:1b:34:12:7c:a9:e6:27:08:30:d2:07:0d:b4:26" and
            1352764799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9b108b8a1daa0d5581f59fcee0447901 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CharacTell Ltd" and (
                pe.signatures[i].serial == "00:9b:10:8b:8a:1d:aa:0d:55:81:f5:9f:ce:e0:44:79:01" or
                pe.signatures[i].serial == "9b:10:8b:8a:1d:aa:0d:55:81:f5:9f:ce:e0:44:79:01"
            ) and
            1380671999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5f8203c430fc7db4e61f6684f6829ffc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Haivision Network Video" and
            pe.signatures[i].serial == "5f:82:03:c4:30:fc:7d:b4:e6:1f:66:84:f6:82:9f:fc" and
            1382572799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6b6daef5be29f20ddce4b0f5e9fa6ea5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Calibration Consultants" and
            pe.signatures[i].serial == "6b:6d:ae:f5:be:29:f2:0d:dc:e4:b0:f5:e9:fa:6e:a5" and
            1280447999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_57d6dff1ef96f01b9430666b2733cc87 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Smart Plugin Ltda" and
            pe.signatures[i].serial == "57:d6:df:f1:ef:96:f0:1b:94:30:66:6b:27:33:cc:87" and
            1314575999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0166b65038d61e5435b48204cae4795a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TOLGA KAPLAN" and
            pe.signatures[i].serial == "01:66:b6:50:38:d6:1e:54:35:b4:82:04:ca:e4:79:5a" and
            1403999999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_784f226b45c3bd8e4089243d747d1f59 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FSPro Labs" and
            pe.signatures[i].serial == "78:4f:22:6b:45:c3:bd:8e:40:89:24:3d:74:7d:1f:59" and
            1242777599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_11690f05604445fae0de539eeeeec584 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tera information Technology co.Ltd" and
            pe.signatures[i].serial == "11:69:0f:05:60:44:45:fa:e0:de:53:9e:ee:ee:c5:84" and
            1294703999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aa146bff4b832bdbfe30b84580356763 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yancheng Peoples Information Technology Service Co., Ltd" and (
                pe.signatures[i].serial == "00:aa:14:6b:ff:4b:83:2b:db:fe:30:b8:45:80:35:67:63" or
                pe.signatures[i].serial == "aa:14:6b:ff:4b:83:2b:db:fe:30:b8:45:80:35:67:63"
            ) and
            1295481599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e86f46b60142092aae81b8f6fa3d9c7c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Syncode Sistemas e Tecnologia Ltda" and (
                pe.signatures[i].serial == "00:e8:6f:46:b6:01:42:09:2a:ae:81:b8:f6:fa:3d:9c:7c" or
                pe.signatures[i].serial == "e8:6f:46:b6:01:42:09:2a:ae:81:b8:f6:fa:3d:9c:7c"
            ) and
            1373932799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1a0fd2a4ef4c2a36ab9c5e8f792a35e2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE9\\x87\\x91\\xE5\\x88\\xA9\\xE5\\xAE\\x8F\\xE6\\x98\\x8C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "1a:0f:d2:a4:ef:4c:2a:36:ab:9c:5e:8f:79:2a:35:e2" and
            1389311999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_53bb753b79a99e61a6e822ac52460c70 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xEB\\x8D\\xB0\\xEC\\x8A\\xA4\\xED\\x81\\xAC\\xED\\x83\\x91\\xEC\\x95\\x84\\xEC\\x9D\\xB4\\xEC\\xBD\\x98" and
            pe.signatures[i].serial == "53:bb:75:3b:79:a9:9e:61:a6:e8:22:ac:52:46:0c:70" and
            1400543999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_83f68fc6834bf8bd2c801a2d1f1acc76 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Helpful Technologies, Inc" and (
                pe.signatures[i].serial == "00:83:f6:8f:c6:83:4b:f8:bd:2c:80:1a:2d:1f:1a:cc:76" or
                pe.signatures[i].serial == "83:f6:8f:c6:83:4b:f8:bd:2c:80:1a:2d:1f:1a:cc:76"
            ) and
            1407715199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f385e765acfb95605c9b35ca4c32f80e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CWI SOFTWARE LTDA" and (
                pe.signatures[i].serial == "00:f3:85:e7:65:ac:fb:95:60:5c:9b:35:ca:4c:32:f8:0e" or
                pe.signatures[i].serial == "f3:85:e7:65:ac:fb:95:60:5c:9b:35:ca:4c:32:f8:0e"
            ) and
            1382313599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f62c9c4efc81caf0d5a2608009d48018 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x94\\x90\\xE5\\xB1\\xB1\\xE4\\xB8\\x87\\xE4\\xB8\\x9C\\xE6\\xB6\\xA6\\xE6\\x92\\xAD\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:f6:2c:9c:4e:fc:81:ca:f0:d5:a2:60:80:09:d4:80:18" or
                pe.signatures[i].serial == "f6:2c:9c:4e:fc:81:ca:f0:d5:a2:60:80:09:d4:80:18"
            ) and
            1292889599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cc8d902da36587c9b2113cd76c3c3f8d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE9\\x87\\x91\\xE4\\xBF\\x8A\\xE5\\x9D\\xA4\\xE8\\xAE\\xA1\\xE7\\xAE\\x97\\xE6\\x9C\\xBA\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x8D\\xE5\\x8A\\xA1\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:cc:8d:90:2d:a3:65:87:c9:b2:11:3c:d7:6c:3c:3f:8d" or
                pe.signatures[i].serial == "cc:8d:90:2d:a3:65:87:c9:b2:11:3c:d7:6c:3c:3f:8d"
            ) and
            1292544000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_328bdcc0f679c4649147fbb3eb0e9bc6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nooly Systems LTD" and
            pe.signatures[i].serial == "32:8b:dc:c0:f6:79:c4:64:91:47:fb:b3:eb:0e:9b:c6" and
            1204847999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5f78149eb4f75eb17404a8143aaeaed7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE5\\x9F\\x9F\\xE8\\x81\\x94\\xE8\\xBD\\xAF\\xE4\\xBB\\xB6\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "5f:78:14:9e:b4:f7:5e:b1:74:04:a8:14:3a:ae:ae:d7" and
            1303116124 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_629d120dd84f9c1688d4da40366fab7a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Delta Controls" and
            pe.signatures[i].serial == "62:9d:12:0d:d8:4f:9c:16:88:d4:da:40:36:6f:ab:7a" and
            1306799999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_039e5d0e3297f574db99e1d9503853d9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cigam Software Corporativo LTDA" and
            pe.signatures[i].serial == "03:9e:5d:0e:32:97:f5:74:db:99:e1:d9:50:38:53:d9" and
            1378079999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bc32bbe5bbb4f06f490c50651cd5da50 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Remedica Medical Education and Publishing Ltd" and (
                pe.signatures[i].serial == "00:bc:32:bb:e5:bb:b4:f0:6f:49:0c:50:65:1c:d5:da:50" or
                pe.signatures[i].serial == "bc:32:bb:e5:bb:b4:f0:6f:49:0c:50:65:1c:d5:da:50"
            ) and
            1387151999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3e1656dfcaacfed7c2d2564355698aa3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "John W.Richard" and
            pe.signatures[i].serial == "3e:16:56:df:ca:ac:fe:d7:c2:d2:56:43:55:69:8a:a3" and
            1385251199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4bf1d68e926e2dd8966008c44f95ea1c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Technical and Commercial Consulting Pvt. Ltd." and
            pe.signatures[i].serial == "4b:f1:d6:8e:92:6e:2d:d8:96:60:08:c4:4f:95:ea:1c" and
            1322092799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_149c12083c145e28155510cfc19db0fe {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3rd Eye Solutions Ltd" and
            pe.signatures[i].serial == "14:9c:12:08:3c:14:5e:28:15:55:10:cf:c1:9d:b0:fe" and
            1209340799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_77e0117e8b2b8faa84bed961019d5ef8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Reiner Wodey Informationssysteme" and
            pe.signatures[i].serial == "77:e0:11:7e:8b:2b:8f:aa:84:be:d9:61:01:9d:5e:f8" and
            1383695999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4f3feb4baf377aea90a463c5dee63884 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "F3D LIMITED" and
            pe.signatures[i].serial == "4f:3f:eb:4b:af:37:7a:ea:90:a4:63:c5:de:e6:38:84" and
            1526601599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3d2580e89526f7852b570654efd9a8bf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing LockerGoga ransomware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MIKL LIMITED" and
            pe.signatures[i].serial == "3d:25:80:e8:95:26:f7:85:2b:57:06:54:ef:d9:a8:bf" and
            1529888400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fffe432a53ff03b9223f88be1b83d9d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing BabyShark malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EGIS Co., Ltd." and
            pe.signatures[i].serial == "0f:ff:e4:32:a5:3f:f0:3b:92:23:f8:8b:e1:b8:3d:9d" and
            1498524050 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_832e161aea5206d815f973e5a1feb3e7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing SeedLocker ransomware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Project NSRM Ltd" and (
                pe.signatures[i].serial == "00:83:2e:16:1a:ea:52:06:d8:15:f9:73:e5:a1:fe:b3:e7" or
                pe.signatures[i].serial == "83:2e:16:1a:ea:52:06:d8:15:f9:73:e5:a1:fe:b3:e7"
            ) and
            1549830060 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_09aecea45bfd40ce7d62d7d711916d7d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALINA LTD" and
            pe.signatures[i].serial == "09:ae:ce:a4:5b:fd:40:ce:7d:62:d7:d7:11:91:6d:7d" and
            1551052800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4ff4eda5fa641e70162713426401f438 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DUHANEY LIMITED" and
            pe.signatures[i].serial == "4f:f4:ed:a5:fa:64:1e:70:16:27:13:42:64:01:f4:38" and
            1555349604 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_067dffc5e3026eb4c62971c98ac8a900 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DVERI FADO, TOV" and
            pe.signatures[i].serial == "06:7d:ff:c5:e3:02:6e:b4:c6:29:71:c9:8a:c8:a9:00" and
            1552176000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b1da219688e51fd0bfac2c891d56cbb8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FIRNEEZ EUROPE LIMITED" and (
                pe.signatures[i].serial == "00:b1:da:21:96:88:e5:1f:d0:bf:ac:2c:89:1d:56:cb:b8" or
                pe.signatures[i].serial == "b1:da:21:96:88:e5:1f:d0:bf:ac:2c:89:1d:56:cb:b8"
            ) and
            1542931200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7289b0f9bd641e3e352dc3183f8de6be {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ICE ACTIVATION LIMITED" and
            pe.signatures[i].serial == "72:89:b0:f9:bd:64:1e:3e:35:2d:c3:18:3f:8d:e6:be" and
            1557933274 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fd7b7a8678a67181a54bc7499eba44da {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IMRAN IT SERVICES LTD" and (
                pe.signatures[i].serial == "00:fd:7b:7a:86:78:a6:71:81:a5:4b:c7:49:9e:ba:44:da" or
                pe.signatures[i].serial == "fd:7b:7a:86:78:a6:71:81:a5:4b:c7:49:9e:ba:44:da"
            ) and
            1548028800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ebbdd6cdeda40ca64513280ecd625c54 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IT PUT LIMITED" and (
                pe.signatures[i].serial == "00:eb:bd:d6:cd:ed:a4:0c:a6:45:13:28:0e:cd:62:5c:54" or
                pe.signatures[i].serial == "eb:bd:d6:cd:ed:a4:0c:a6:45:13:28:0e:cd:62:5c:54"
            ) and
            1549238400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_61da676c1dcfcf188276e2c70d68082e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "P2N ONLINE LTD" and
            pe.signatures[i].serial == "61:da:67:6c:1d:cf:cf:18:82:76:e2:c7:0d:68:08:2e" and
            1552723954 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_767436921b2698bd18400a24b01341b6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REBROSE LEISURE LIMITED" and
            pe.signatures[i].serial == "76:74:36:92:1b:26:98:bd:18:40:0a:24:b0:13:41:b6" and
            1556284480 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3e795531b3265510f935187eca59920a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "sasha catering ltd" and
            pe.signatures[i].serial == "3e:79:55:31:b3:26:55:10:f9:35:18:7e:ca:59:92:0a" and
            1557243644 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8f40b1485309a064a28b96bfa3f55f36 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Singh Agile Content Design Limited" and (
                pe.signatures[i].serial == "00:8f:40:b1:48:53:09:a0:64:a2:8b:96:bf:a3:f5:5f:36" or
                pe.signatures[i].serial == "8f:40:b1:48:53:09:a0:64:a2:8b:96:bf:a3:f5:5f:36"
            ) and
            1542585600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b2120facadbb92cc0a176759604c6a0f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLON LTD" and (
                pe.signatures[i].serial == "00:b2:12:0f:ac:ad:bb:92:cc:0a:17:67:59:60:4c:6a:0f" or
                pe.signatures[i].serial == "b2:12:0f:ac:ad:bb:92:cc:0a:17:67:59:60:4c:6a:0f"
            ) and
            1554249600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4f407eb50803845cc43937823e1344c0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLOW COOKED VENTURES LTD" and
            pe.signatures[i].serial == "4f:40:7e:b5:08:03:84:5c:c4:39:37:82:3e:13:44:c0" and
            1556555362 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6922bb5de88e4127e1ac6969e6a199f5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SMACHNA PLITKA, TOV" and
            pe.signatures[i].serial == "69:22:bb:5d:e8:8e:41:27:e1:ac:69:69:e6:a1:99:f5" and
            1552692162 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_73065efa163b7901fa1ccb0a54e80540 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SOVA CONSULTANCY LTD" and
            pe.signatures[i].serial == "73:06:5e:fa:16:3b:79:01:fa:1c:cb:0a:54:e8:05:40" and
            1548115200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4842afad00904ed8c98811e652ccb3b7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\"VERY EXCLUSIVE LTD\"" and
            pe.signatures[i].serial == "48:42:af:ad:00:90:4e:d8:c9:88:11:e6:52:cc:b3:b7" and
            1545177600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5a59a686b4a904d0fca07153ea6db6cc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABADAN PIZZA LTD" and
            pe.signatures[i].serial == "5a:59:a6:86:b4:a9:04:d0:fc:a0:71:53:ea:6d:b6:cc" and
            1563403380 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0b6d8152f4a06ba781c6677eea5ab74b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GLARYSOFT LTD" and
            pe.signatures[i].serial == "0b:6d:81:52:f4:a0:6b:a7:81:c6:67:7e:ea:5a:b7:4b" and
            1568246400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3ad60cea73e1dd1a3e6c02d9b339c380 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CUS Software GmbH" and
            pe.signatures[i].serial == "3a:d6:0c:ea:73:e1:dd:1a:3e:6c:02:d9:b3:39:c3:80" and
            1567036800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7df2dfed47c6fd6542131847cffbc102 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AFVIMPEX SRL" and
            pe.signatures[i].serial == "7d:f2:df:ed:47:c6:fd:65:42:13:18:47:cf:fb:c1:02" and
            1567036800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_74fedf0f8398060fa8378c6d174465c8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DOCS PTY LTD" and
            pe.signatures[i].serial == "74:fe:df:0f:83:98:06:0f:a8:37:8c:6d:17:44:65:c8" and
            1566172800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3bd6a5bba28e7c1ca44880159dace237 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TECHNO BEAVERS LIMITED" and
            pe.signatures[i].serial == "3b:d6:a5:bb:a2:8e:7c:1c:a4:48:80:15:9d:ac:e2:37" and
            1563408000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c04f8f1e00c69e96a51bf14aab1c6ae0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CHAIKA, TOV" and (
                pe.signatures[i].serial == "00:c0:4f:8f:1e:00:c6:9e:96:a5:1b:f1:4a:ab:1c:6a:e0" or
                pe.signatures[i].serial == "c0:4f:8f:1e:00:c6:9e:96:a5:1b:f1:4a:ab:1c:6a:e0"
            ) and
            1551398400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_23f537ce13c6cccdfd3f8ce81fb981cb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ISECURE GROUP PTY LTD" and
            pe.signatures[i].serial == "23:f5:37:ce:13:c6:cc:cd:fd:3f:8c:e8:1f:b9:81:cb" and
            1566086400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_73ecfdbb99aec176ddfcf7958d120e1a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MHOW PTY LTD" and
            pe.signatures[i].serial == "73:ec:fd:bb:99:ae:c1:76:dd:fc:f7:95:8d:12:0e:1a" and
            1566864000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_675129bb174a5b05e330cc09f8bbd70a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALEX & CO PTY LIMITED" and
            pe.signatures[i].serial == "67:51:29:bb:17:4a:5b:05:e3:30:cc:09:f8:bb:d7:0a" and
            1565568000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_de13fe2dbb8f890287e1780aff6ffd22 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LAST TIME PTY LTD" and
            pe.signatures[i].serial == "de:13:fe:2d:bb:8f:89:02:87:e1:78:0a:ff:6f:fd:22" and
            1566259200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_da000d18949c247d4ddfc2585cc8bd0f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PORT-SERVIS LTD" and (
                pe.signatures[i].serial == "00:da:00:0d:18:94:9c:24:7d:4d:df:c2:58:5c:c8:bd:0f" or
                pe.signatures[i].serial == "da:00:0d:18:94:9c:24:7d:4d:df:c2:58:5c:c8:bd:0f"
            ) and
            1564444800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06e842d3ea6249d783d6b55e29c060c7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PORT-SERVIS LTD, TOV" and
            pe.signatures[i].serial == "06:e8:42:d3:ea:62:49:d7:83:d6:b5:5e:29:c0:60:c7" and
            1565568000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06473c3c19d9e1a9429b58b6faec2967 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digital Leadership Solutions Limited" and
            pe.signatures[i].serial == "06:47:3c:3c:19:d9:e1:a9:42:9b:58:b6:fa:ec:29:67" and
            1581984001 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_39f56251df2088223cc03494084e6081 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Inter Med Pty. Ltd." and
            pe.signatures[i].serial == "39:f5:62:51:df:20:88:22:3c:c0:34:94:08:4e:60:81" and
            1583539200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1362e56d34dc7b501e17fa1ac3c3e3d9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO  \"Amaranth\"" and
            pe.signatures[i].serial == "13:62:e5:6d:34:dc:7b:50:1e:17:fa:1a:c3:c3:e3:d9" and
            1575936000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4b83593fc78d92cfaa9bdf3f97383964 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Kometa" and
            pe.signatures[i].serial == "4b:83:59:3f:c7:8d:92:cf:aa:9b:df:3f:97:38:39:64" and
            1579996800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c7505e7464e00ec1dccd8d1b466d15ff {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ltd. \"Eve Beauty\"" and (
                pe.signatures[i].serial == "00:c7:50:5e:74:64:e0:0e:c1:dc:cd:8d:1b:46:6d:15:ff" or
                pe.signatures[i].serial == "c7:50:5e:74:64:e0:0e:c1:dc:cd:8d:1b:46:6d:15:ff"
            ) and
            1583824676 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cbf91988fb83511de1b3a7a520712e9c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ltd. \"Eve Beauty\"" and (
                pe.signatures[i].serial == "00:cb:f9:19:88:fb:83:51:1d:e1:b3:a7:a5:20:71:2e:9c" or
                pe.signatures[i].serial == "cb:f9:19:88:fb:83:51:1d:e1:b3:a7:a5:20:71:2e:9c"
            ) and
            1578786662 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ce3675ae4abfe688870bcacb63060f4f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO \"MPS\"" and (
                pe.signatures[i].serial == "00:ce:36:75:ae:4a:bf:e6:88:87:0b:ca:cb:63:06:0f:4f" or
                pe.signatures[i].serial == "ce:36:75:ae:4a:bf:e6:88:87:0b:ca:cb:63:06:0f:4f"
            ) and
            1582675200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9813229efe0046d23542cc7569d5a403 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO \"MPS\"" and (
                pe.signatures[i].serial == "00:98:13:22:9e:fe:00:46:d2:35:42:cc:75:69:d5:a4:03" or
                pe.signatures[i].serial == "98:13:22:9e:fe:00:46:d2:35:42:cc:75:69:d5:a4:03"
            ) and
            1575849600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_86e5a9b9e89e5075c475006d0ca03832 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BlueMarble GmbH" and (
                pe.signatures[i].serial == "00:86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32" or
                pe.signatures[i].serial == "86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32"
            ) and
            1574791194 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_075dca9ca84b93e8a89b775128f90302 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UAB GT-servis" and
            pe.signatures[i].serial == "07:5d:ca:9c:a8:4b:93:e8:a8:9b:77:51:28:f9:03:02" and
            1579305601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0ddce8cdc91b5b649bb4b45ffbba6c6c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLIM DOG GROUP SP Z O O" and
            pe.signatures[i].serial == "0d:dc:e8:cd:c9:1b:5b:64:9b:b4:b4:5f:fb:ba:6c:6c" and
            1580722435 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9bd614d5869bb66c96b67e154d517384 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\"CENTR MBP\"" and (
                pe.signatures[i].serial == "00:9b:d6:14:d5:86:9b:b6:6c:96:b6:7e:15:4d:51:73:84" or
                pe.signatures[i].serial == "9b:d6:14:d5:86:9b:b6:6c:96:b6:7e:15:4d:51:73:84"
            ) and
            1581618180 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_540cea639d5d48669b7f2f64 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CENTR MBP LLC" and
            pe.signatures[i].serial == "54:0c:ea:63:9d:5d:48:66:9b:7f:2f:64" and
            1570871755 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03a7748a4355020a652466b5e02e07de {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Teleneras MB" and
            pe.signatures[i].serial == "03:a7:74:8a:43:55:02:0a:65:24:66:b5:e0:2e:07:de" and
            1575244801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b881a72d4117bbc38b81d3c65c792c1a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Red GmbH" and (
                pe.signatures[i].serial == "00:b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a" or
                pe.signatures[i].serial == "b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a"
            ) and
            1581936420 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08653ef2ed9e6ebb56ffa7e93f963235 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Haw Farm LIMITED" and
            pe.signatures[i].serial == "08:65:3e:f2:ed:9e:6e:bb:56:ff:a7:e9:3f:96:32:35" and
            1581465601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9c4816d900a6ecdbe54adf72b19ebcf5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Datamingo Limited" and (
                pe.signatures[i].serial == "00:9c:48:16:d9:00:a6:ec:db:e5:4a:df:72:b1:9e:bc:f5" or
                pe.signatures[i].serial == "9c:48:16:d9:00:a6:ec:db:e5:4a:df:72:b1:9e:bc:f5"
            ) and
            1557187200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_269174f9fe7c6ed4e1d19b26c3f5b35f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GO ONLINE d.o.o." and
            pe.signatures[i].serial == "26:91:74:f9:fe:7c:6e:d4:e1:d1:9b:26:c3:f5:b3:5f" and
            1586386919 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_523fb4036368dc26192d68827f2d889b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO MEDUZA SERVICE GROUP" and
            pe.signatures[i].serial == "52:3f:b4:03:63:68:dc:26:19:2d:68:82:7f:2d:88:9b" and
            1586847880 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_84f842f6d33cd2f25b88dd1710e21137 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DataNext s.r.o." and (
                pe.signatures[i].serial == "00:84:f8:42:f6:d3:3c:d2:f2:5b:88:dd:17:10:e2:11:37" or
                pe.signatures[i].serial == "84:f8:42:f6:d3:3c:d2:f2:5b:88:dd:17:10:e2:11:37"
            ) and
            1586775720 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4fbcaa289ba925b4e247809b6b028202 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kimjac ApS" and
            pe.signatures[i].serial == "4f:bc:aa:28:9b:a9:25:b4:e2:47:80:9b:6b:02:82:02" and
            1588227220 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1f2e8effbb08c7dbcc7a7f2d835457b5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RTI, OOO" and
            pe.signatures[i].serial == "1f:2e:8e:ff:bb:08:c7:db:cc:7a:7f:2d:83:54:57:b5" and
            1581382360 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aeba4c39306fdd022849867801645814 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SK AI MAS GmbH" and (
                pe.signatures[i].serial == "00:ae:ba:4c:39:30:6f:dd:02:28:49:86:78:01:64:58:14" or
                pe.signatures[i].serial == "ae:ba:4c:39:30:6f:dd:02:28:49:86:78:01:64:58:14"
            ) and
            1579478400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_028d50ae0c554b49148e82db5b1c2699 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VAS CO PTY LTD" and
            pe.signatures[i].serial == "02:8d:50:ae:0c:55:4b:49:14:8e:82:db:5b:1c:26:99" and
            1579478400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_684f478c7259dde0cfe2260112ca9846 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC \"IP EM\"" and
            pe.signatures[i].serial == "68:4f:47:8c:72:59:dd:e0:cf:e2:26:01:12:ca:98:46" and
            1584981648 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0b7c32208a954a483dd102e1be094867 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Win Sp Z O O" and
            pe.signatures[i].serial == "0b:7c:32:20:8a:95:4a:48:3d:d1:02:e1:be:09:48:67" and
            1583884800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3e72daf2b9a4449e946009e5084a8e76 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Infoteh63" and
            pe.signatures[i].serial == "3e:72:da:f2:b9:a4:44:9e:94:60:09:e5:08:4a:8e:76" and
            1591787570 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_11edd343e21c36ac985555d85c16135f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pribyl Handels GmbH" and
            pe.signatures[i].serial == "11:ed:d3:43:e2:1c:36:ac:98:55:55:d8:5c:16:13:5f" and
            1589925600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_093fe63d1a5f68f14ecaac871a03f7a3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SPECTACLE IMAGE LTD" and
            pe.signatures[i].serial == "09:3f:e6:3d:1a:5f:68:f1:4e:ca:ac:87:1a:03:f7:a3" and
            1562716800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bb26b7b6634d5db548c437b5085b01c1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO \"IT Mott\"" and (
                pe.signatures[i].serial == "00:bb:26:b7:b6:63:4d:5d:b5:48:c4:37:b5:08:5b:01:c1" or
                pe.signatures[i].serial == "bb:26:b7:b6:63:4d:5d:b5:48:c4:37:b5:08:5b:01:c1"
            ) and
            1591919307 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_29128a56e7b3bfb230742591ac8b4718 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Programavimo paslaugos, MB" and
            pe.signatures[i].serial == "29:12:8a:56:e7:b3:bf:b2:30:74:25:91:ac:8b:47:18" and
            1590900909 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7bfbfdfef43608730ee14779ee3ee2cb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CSTech Software Inc." and
            pe.signatures[i].serial == "7b:fb:fd:fe:f4:36:08:73:0e:e1:47:79:ee:3e:e2:cb" and
            1590537600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_62205361a758b00572d417cba014f007 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UNITEKH-S, OOO" and
            pe.signatures[i].serial == "62:20:53:61:a7:58:b0:05:72:d4:17:cb:a0:14:f0:07" and
            1590470683 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4b47d18dbea57abd1563ddf89f87a6c2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KBK, OOO" and
            pe.signatures[i].serial == "4b:47:d1:8d:be:a5:7a:bd:15:63:dd:f8:9f:87:a6:c2" and
            1590485607 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_be41e2c7bb2493044b9241abb732599d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Company Babylon" and (
                pe.signatures[i].serial == "00:be:41:e2:c7:bb:24:93:04:4b:92:41:ab:b7:32:59:9d" or
                pe.signatures[i].serial == "be:41:e2:c7:bb:24:93:04:4b:92:41:ab:b7:32:59:9d"
            ) and
            1589146251 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_15c5af15afecf1c900cbab0ca9165629 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kompaniya Auttek" and
            pe.signatures[i].serial == "15:c5:af:15:af:ec:f1:c9:00:cb:ab:0c:a9:16:56:29" and
            1586091840 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_476de2f108d20b43ba3bae6f331af8f1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digiwill Limited" and
            pe.signatures[i].serial == "47:6d:e2:f1:08:d2:0b:43:ba:3b:ae:6f:33:1a:f8:f1" and
            1588135722 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08ddcc67f8cad6929607e4cda29b3503 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FAN-CHAI, TOV" and
            pe.signatures[i].serial == "08:dd:cc:67:f8:ca:d6:92:96:07:e4:cd:a2:9b:35:03" and
            1564310268 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_052242ace583adf2a3b96adcb04d0812 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FAN-CHAI, TOV" and
            pe.signatures[i].serial == "05:22:42:ac:e5:83:ad:f2:a3:b9:6a:dc:b0:4d:08:12" and
            1573603200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bebef5c533ce92efc402fab8605c43ec {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO VEKTOR" and (
                pe.signatures[i].serial == "00:be:be:f5:c5:33:ce:92:ef:c4:02:fa:b8:60:5c:43:ec" or
                pe.signatures[i].serial == "be:be:f5:c5:33:ce:92:ef:c4:02:fa:b8:60:5c:43:ec"
            ) and
            1587513600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1d3f39f481fe067f8a9289bb49e05a04 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LOGIKA, OOO" and
            pe.signatures[i].serial == "1d:3f:39:f4:81:fe:06:7f:8a:92:89:bb:49:e0:5a:04" and
            1592553220 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7be35d025e65cc7a4ee01f72 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Logika OOO" and
            pe.signatures[i].serial == "7b:e3:5d:02:5e:65:cc:7a:4e:e0:1f:72" and
            1594976445 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_351fe2efdc0ac56a0c822cf8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Logika OOO" and
            pe.signatures[i].serial == "35:1f:e2:ef:dc:0a:c5:6a:0c:82:2c:f8" and
            1594976475 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9cfbb4c69008821aaacecde97ee149ab {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kivaliz Prest s.r.l." and (
                pe.signatures[i].serial == "00:9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab" or
                pe.signatures[i].serial == "9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab"
            ) and
            1592363914 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c04f5d17af872cb2c37e3367fe761d0d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DES SP Z O O" and (
                pe.signatures[i].serial == "00:c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d" or
                pe.signatures[i].serial == "c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d"
            ) and
            1594590024 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_02c5351936abe405ac760228a40387e8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RESURS-RM OOO" and
            pe.signatures[i].serial == "02:c5:35:19:36:ab:e4:05:ac:76:02:28:a4:03:87:e8" and
            1589932801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1ecd829adcc55d9d6afe30dc371ebda6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Komp.IT" and (
                pe.signatures[i].serial == "00:1e:cd:82:9a:dc:c5:5d:9d:6a:fe:30:dc:37:1e:bd:a6" or
                pe.signatures[i].serial == "1e:cd:82:9a:dc:c5:5d:9d:6a:fe:30:dc:37:1e:bd:a6"
            ) and
            1588723200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b0167124ca59149e64d292eb4b142014 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Euro May SP Z O O" and (
                pe.signatures[i].serial == "00:b0:16:71:24:ca:59:14:9e:64:d2:92:eb:4b:14:20:14" or
                pe.signatures[i].serial == "b0:16:71:24:ca:59:14:9e:64:d2:92:eb:4b:14:20:14"
            ) and
            1585267200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_112613b7b5f696cf377680f6463fcc8c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Infoware Cloud Limited" and
            pe.signatures[i].serial == "11:26:13:b7:b5:f6:96:cf:37:76:80:f6:46:3f:cc:8c" and
            1566518400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b3f906e5e6b2cf61c5e51be79b4e8777 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Accelerate Technologies Ltd" and (
                pe.signatures[i].serial == "00:b3:f9:06:e5:e6:b2:cf:61:c5:e5:1b:e7:9b:4e:87:77" or
                pe.signatures[i].serial == "b3:f9:06:e5:e6:b2:cf:61:c5:e5:1b:e7:9b:4e:87:77"
            ) and
            1594900020 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_566ac16a57b132d3f64dced14de790ee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unirad LLC" and
            pe.signatures[i].serial == "56:6a:c1:6a:57:b1:32:d3:f6:4d:ce:d1:4d:e7:90:ee" and
            1562889600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d2caf7908aaebfa1a8f3e2136fece024 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FANATOR, OOO" and (
                pe.signatures[i].serial == "00:d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24" or
                pe.signatures[i].serial == "d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24"
            ) and
            1599041760 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e04a344b397f752a45b128a594a3d6b5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Highweb Ireland Operations Limited" and (
                pe.signatures[i].serial == "00:e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5" or
                pe.signatures[i].serial == "e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5"
            ) and
            1597708800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3bcaed3ef678f2f9bf38d09e149b8d70 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "StarY Media Inc." and
            pe.signatures[i].serial == "3b:ca:ed:3e:f6:78:f2:f9:bf:38:d0:9e:14:9b:8d:70" and
            1599091200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_56d576a062491ea0a5877ced418203a1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Silvo LLC" and
            pe.signatures[i].serial == "56:d5:76:a0:62:49:1e:a0:a5:87:7c:ed:41:82:03:a1" and
            1596249885 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fcba260df7da602ecf4d4d6fc89d5dd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Gold Stroy SP Z O O" and
            pe.signatures[i].serial == "0f:cb:a2:60:df:7d:a6:02:ec:f4:d4:d6:fc:89:d5:dd" and
            1593388801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4152169f22454ed604d03555b7afb175 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SMACKTECH SOFTWARE LIMITED" and
            pe.signatures[i].serial == "41:52:16:9f:22:45:4e:d6:04:d0:35:55:b7:af:b1:75" and
            1595808000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_01c88ccbd219500139d1af138a9e898e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Raymond Yanagita" and
            pe.signatures[i].serial == "01:c8:8c:cb:d2:19:50:01:39:d1:af:13:8a:9e:89:8e" and
            1593041280 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_41d05676e0d31908be4dead3486aeae3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rov SP Z O O" and
            pe.signatures[i].serial == "41:d0:56:76:e0:d3:19:08:be:4d:ea:d3:48:6a:ea:e3" and
            1594857600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8cff807edaf368a60e4106906d8df319 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KRAFT BOKS OOO" and (
                pe.signatures[i].serial == "00:8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19" or
                pe.signatures[i].serial == "8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19"
            ) and
            1598334455 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a3e62be1572293ad618f58a8aa32857f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ISIDA, TOV" and (
                pe.signatures[i].serial == "00:a3:e6:2b:e1:57:22:93:ad:61:8f:58:a8:aa:32:85:7f" or
                pe.signatures[i].serial == "a3:e6:2b:e1:57:22:93:ad:61:8f:58:a8:aa:32:85:7f"
            ) and
            1596585600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_672d4428450afcc24fc60969a5063a3e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MEP, OOO" and
            pe.signatures[i].serial == "67:2d:44:28:45:0a:fc:c2:4f:c6:09:69:a5:06:3a:3e" and
            1597381260 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_df479e14a70c7970a4de3dd3e4bb0318 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SOFTWARE HUB IT LTD" and (
                pe.signatures[i].serial == "00:df:47:9e:14:a7:0c:79:70:a4:de:3d:d3:e4:bb:03:18" or
                pe.signatures[i].serial == "df:47:9e:14:a7:0c:79:70:a4:de:3d:d3:e4:bb:03:18"
            ) and
            1591660800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2924785fd7990b2d510675176dae2bed {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Neoopt LLC" and
            pe.signatures[i].serial == "29:24:78:5f:d7:99:0b:2d:51:06:75:17:6d:ae:2b:ed" and
            1595000258 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f4d2def53bccb0dd2b7d54e4853a2fc5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PETROYL GROUP, TOV" and (
                pe.signatures[i].serial == "00:f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5" or
                pe.signatures[i].serial == "f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5"
            ) and
            1598347687 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03bf9ef4cf037a2385649026c3da9d3e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "COLLECTIVE SOFTWARE INC." and
            pe.signatures[i].serial == "03:bf:9e:f4:cf:03:7a:23:85:64:90:26:c3:da:9d:3e" and
            1595371955 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_790177a54209d55560a55db97c5900d6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MAK GmbH" and
            pe.signatures[i].serial == "79:01:77:a5:42:09:d5:55:60:a5:5d:b9:7c:59:00:d6" and
            1594080000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_048f7b5f67d8e2b3030f75eb7be2713d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RITEIL SERVIS, OOO" and
            pe.signatures[i].serial == "04:8f:7b:5f:67:d8:e2:b3:03:0f:75:eb:7b:e2:71:3d" and
            1591142400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_082023879112289bf351d297cc8efcfc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STA-R TOV" and
            pe.signatures[i].serial == "08:20:23:87:91:12:28:9b:f3:51:d2:97:cc:8e:fc:fc" and
            1573430400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0d53690631dd186c56be9026eb931ae2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STA-R TOV" and
            pe.signatures[i].serial == "0d:53:69:06:31:dd:18:6c:56:be:90:26:eb:93:1a:e2" and
            1592190240 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_32119925a6ce4710aecc4006c28e749f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Maxiol" and
            pe.signatures[i].serial == "32:11:99:25:a6:ce:47:10:ae:cc:40:06:c2:8e:74:9f" and
            1592438400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2c90eaf4de3afc03ba924c719435c2a3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AntiFIX s.r.o." and (
                pe.signatures[i].serial == "00:2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3" or
                pe.signatures[i].serial == "2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3"
            ) and
            1586293430 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aff762e907f0644e76ed8a7485fb12a1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lets Start SP Z O O" and (
                pe.signatures[i].serial == "00:af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1" or
                pe.signatures[i].serial == "af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1"
            ) and
            1594882330 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d8530214ca0f512946496b5164c61201 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DJ ONLINE MARKETING LIMITED" and (
                pe.signatures[i].serial == "00:d8:53:02:14:ca:0f:51:29:46:49:6b:51:64:c6:12:01" or
                pe.signatures[i].serial == "d8:53:02:14:ca:0f:51:29:46:49:6b:51:64:c6:12:01"
            ) and
            1595485920 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_661ba8f3c9d1b348413484e9a49502f7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unique Digital Services Ltd." and (
                pe.signatures[i].serial == "00:66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7" or
                pe.signatures[i].serial == "66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7"
            ) and
            1594942800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_51aead5a9ab2d841b449fa82de3a8a00 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Corsair Software Solution Inc." and
            pe.signatures[i].serial == "51:ae:ad:5a:9a:b2:d8:41:b4:49:fa:82:de:3a:8a:00" and
            1501577475 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03b630f9645531f8868dae8ac0f8cfe6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Geksan LLC" and
            pe.signatures[i].serial == "03:b6:30:f9:64:55:31:f8:86:8d:ae:8a:c0:f8:cf:e6" and
            1594252801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6f8373cf89f1b49138f4328118487f9e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "30 PTY LTD" and
            pe.signatures[i].serial == "6f:83:73:cf:89:f1:b4:91:38:f4:32:81:18:48:7f:9e" and
            1572566400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e38259cf24cc702ce441b683ad578911 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Akhirah Technologies Inc." and (
                pe.signatures[i].serial == "00:e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11" or
                pe.signatures[i].serial == "e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11"
            ) and
            1597276800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bdc81bc76090dae0eee2e1eb744a4f9a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALM4U GmbH" and (
                pe.signatures[i].serial == "00:bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a" or
                pe.signatures[i].serial == "bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a"
            ) and
            1579824000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b2e730b0526f36faf7d093d48d6d9997 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bamboo Connect s.r.o." and (
                pe.signatures[i].serial == "00:b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97" or
                pe.signatures[i].serial == "b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97"
            ) and
            1597276800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7156ec47ef01ab8359ef4304e5af1a05 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BOREC, OOO" and
            pe.signatures[i].serial == "71:56:ec:47:ef:01:ab:83:59:ef:43:04:e5:af:1a:05" and
            1597363200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_13794371c052ec0559e9b492abb25c26 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Carmel group LLC" and
            pe.signatures[i].serial == "13:79:43:71:c0:52:ec:05:59:e9:b4:92:ab:b2:5c:26" and
            1599177600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5c7e78f53c31d6aa5b45de14b47eb5c4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cubic Information Systems, UAB" and
            pe.signatures[i].serial == "5c:7e:78:f5:3c:31:d6:aa:5b:45:de:14:b4:7e:b5:c4" and
            1579824000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_dadf44e4046372313ee97b8e394c4079 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digital Capital Management Ireland Limited" and (
                pe.signatures[i].serial == "00:da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79" or
                pe.signatures[i].serial == "da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79"
            ) and
            1600244736 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f8c2e08438bb0e9adc955e4b493e5821 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DocsGen Software Solutions Inc." and (
                pe.signatures[i].serial == "00:f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21" or
                pe.signatures[i].serial == "f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21"
            ) and
            1599523200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_70e1ebd170db8102d8c28e58392e5632 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Equal Cash Technologies Limited" and
            pe.signatures[i].serial == "70:e1:eb:d1:70:db:81:02:d8:c2:8e:58:39:2e:56:32" and
            1599264000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_09c89de6f64a7fdf657e69353c5fdd44 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EXON RENTAL SP Z O O" and
            pe.signatures[i].serial == "09:c8:9d:e6:f6:4a:7f:df:65:7e:69:35:3c:5f:dd:44" and
            1601337601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ffff2ce862378b26440df49ca9175b70 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "F & A.TIM d.o.o." and (
                pe.signatures[i].serial == "00:ff:ff:2c:e8:62:37:8b:26:44:0d:f4:9c:a9:17:5b:70" or
                pe.signatures[i].serial == "ff:ff:2c:e8:62:37:8b:26:44:0d:f4:9c:a9:17:5b:70"
            ) and
            1576195200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3223b4616c2687c04865bee8321726a8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and
            pe.signatures[i].serial == "32:23:b4:61:6c:26:87:c0:48:65:be:e8:32:17:26:a8" and
            1601337600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7709d2df39e9a4f7db2f3cbc29b49743 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Grina LLC" and
            pe.signatures[i].serial == "77:09:d2:df:39:e9:a4:f7:db:2f:3c:bc:29:b4:97:43" and
            1556353331 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e29690e14518874d2dcf00234ae94f1f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GRIND & TAMP ENTERPRISES PTY LTD" and (
                pe.signatures[i].serial == "00:e2:96:90:e1:45:18:87:4d:2d:cf:00:23:4a:e9:4f:1f" or
                pe.signatures[i].serial == "e2:96:90:e1:45:18:87:4d:2d:cf:00:23:4a:e9:4f:1f"
            ) and
            1570838400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cfac705c7e6845904f99995324f7562c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HMWOCFPSDLAFMFZIVD" and (
                pe.signatures[i].serial == "cf:ac:70:5c:7e:68:45:90:4f:99:99:53:24:f7:56:2c" or
                pe.signatures[i].serial == "30:53:8f:a3:81:97:ba:6f:b0:66:66:ac:db:08:a9:d4"
            ) and
            1601918720 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a7989f8be0c82d35a19e7b3dd4be30e5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Instamix Limited" and (
                pe.signatures[i].serial == "00:a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5" or
                pe.signatures[i].serial == "a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5"
            ) and
            1598054400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fa13ae98e17ae23fcfe7ae873d0c120 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KLAKSON, LLC" and
            pe.signatures[i].serial == "0f:a1:3a:e9:8e:17:ae:23:fc:fe:7a:e8:73:d0:c1:20" and
            1597276801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3696883055975d571199c6b5d48f3cd5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Korist Networks Incorporated" and
            pe.signatures[i].serial == "36:96:88:30:55:97:5d:57:11:99:c6:b5:d4:8f:3c:d5" and
            1600069289 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ee678930d5bdfaa2ab0172fa4c10ae07 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LEX CORPORATION PTY LTD" and (
                pe.signatures[i].serial == "00:ee:67:89:30:d5:bd:fa:a2:ab:01:72:fa:4c:10:ae:07" or
                pe.signatures[i].serial == "ee:67:89:30:d5:bd:fa:a2:ab:01:72:fa:4c:10:ae:07"
            ) and
            1571011200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d7c432e8d4edef515bfb9d1c214ff0f5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC \"MILKY PUT\"" and (
                pe.signatures[i].serial == "00:d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5" or
                pe.signatures[i].serial == "d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5"
            ) and
            1601596800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5b440a47e8ce3dd202271e5c7a666c78 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Master Networking s.r.o." and
            pe.signatures[i].serial == "5b:44:0a:47:e8:ce:3d:d2:02:27:1e:5c:7a:66:6c:78" and
            1601895571 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b82c6553b2186c219797621aaa233edb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MC Commerce SP Z o o" and (
                pe.signatures[i].serial == "00:b8:2c:65:53:b2:18:6c:21:97:97:62:1a:aa:23:3e:db" or
                pe.signatures[i].serial == "b8:2c:65:53:b2:18:6c:21:97:97:62:1a:aa:23:3e:db"
            ) and
            1585785600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f360f7ad0ed065fec0b44f98e04481a0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MEHANIKUM OOO" and (
                pe.signatures[i].serial == "00:f3:60:f7:ad:0e:d0:65:fe:c0:b4:4f:98:e0:44:81:a0" or
                pe.signatures[i].serial == "f3:60:f7:ad:0e:d0:65:fe:c0:b4:4f:98:e0:44:81:a0"
            ) and
            1599031121 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fe41941464b9992a69b7317418ae8eb7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Milsean Software Limited" and (
                pe.signatures[i].serial == "00:fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7" or
                pe.signatures[i].serial == "fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7"
            ) and
            1599523200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c14b611a44a1bae0e8c7581651845b6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NEEDCODE SP Z O O" and
            pe.signatures[i].serial == "0c:14:b6:11:a4:4a:1b:ae:0e:8c:75:81:65:18:45:b6" and
            1600300801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_690910dc89d7857c3500fb74bed2b08d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OLIMP STROI, OOO" and
            pe.signatures[i].serial == "69:09:10:dc:89:d7:85:7c:35:00:fb:74:be:d2:b0:8d" and
            1597276800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fd41e6bd7428d3008c8a05f68c9ac6f2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OM-FAS d.o.o." and (
                pe.signatures[i].serial == "00:fd:41:e6:bd:74:28:d3:00:8c:8a:05:f6:8c:9a:c6:f2" or
                pe.signatures[i].serial == "fd:41:e6:bd:74:28:d3:00:8c:8a:05:f6:8c:9a:c6:f2"
            ) and
            1575590400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c7079866c0e48b01246ba0c148e70d4d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO GARANT" and (
                pe.signatures[i].serial == "00:c7:07:98:66:c0:e4:8b:01:24:6b:a0:c1:48:e7:0d:4d" or
                pe.signatures[i].serial == "c7:07:98:66:c0:e4:8b:01:24:6b:a0:c1:48:e7:0d:4d"
            ) and
            1588679105 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d591da22f33c800a7024aecff2cd6c6d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO T2 Soft" and (
                pe.signatures[i].serial == "00:d5:91:da:22:f3:3c:80:0a:70:24:ae:cf:f2:cd:6c:6d" or
                pe.signatures[i].serial == "d5:91:da:22:f3:3c:80:0a:70:24:ae:cf:f2:cd:6c:6d"
            ) and
            1588679107 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b36e0f2053caee9c3b966f7be0b40fc3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PARTS-JEST d.o.o." and (
                pe.signatures[i].serial == "00:b3:6e:0f:20:53:ca:ee:9c:3b:96:6f:7b:e0:b4:0f:c3" or
                pe.signatures[i].serial == "b3:6e:0f:20:53:ca:ee:9c:3b:96:6f:7b:e0:b4:0f:c3"
            ) and
            1600172855 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5b320a2f46c99c1ba1357bee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REGION TOURISM LLC" and
            pe.signatures[i].serial == "5b:32:0a:2f:46:c9:9c:1b:a1:35:7b:ee" and
            1602513116 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08d4352185317271c1cec9d05c279af7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Retalit LLC" and
            pe.signatures[i].serial == "08:d4:35:21:85:31:72:71:c1:ce:c9:d0:5c:27:9a:f7" and
            1596585601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b514e4c5309ef9f27add05bedd4339a0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SCABONE PTY LTD" and (
                pe.signatures[i].serial == "00:b5:14:e4:c5:30:9e:f9:f2:7a:dd:05:be:dd:43:39:a0" or
                pe.signatures[i].serial == "b5:14:e4:c5:30:9e:f9:f2:7a:dd:05:be:dd:43:39:a0"
            ) and
            1572566400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_13c7b92282aae782bfb00baf879935f4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and
            pe.signatures[i].serial == "13:c7:b9:22:82:aa:e7:82:bf:b0:0b:af:87:99:35:f4" and
            1603130510 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d627f1000d12485995514bfbdefc55d9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THREE D CORPORATION PTY LTD" and (
                pe.signatures[i].serial == "00:d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9" or
                pe.signatures[i].serial == "d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9"
            ) and
            1597622400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5fb6bae8834edd8d3d58818edc86d7d7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tramplink LLC" and
            pe.signatures[i].serial == "5f:b6:ba:e8:83:4e:dd:8d:3d:58:81:8e:dc:86:d7:d7" and
            1600781989 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e5ad42c509a7c24605530d35832c091e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VESNA, OOO" and (
                pe.signatures[i].serial == "00:e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e" or
                pe.signatures[i].serial == "e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e"
            ) and
            1600786458 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8e3d89c682f7c0dad70110cb7b7c8263 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WORK PLACEMENTS INTERNATIONAL LIMITED" and (
                pe.signatures[i].serial == "00:8e:3d:89:c6:82:f7:c0:da:d7:01:10:cb:7b:7c:82:63" or
                pe.signatures[i].serial == "8e:3d:89:c6:82:f7:c0:da:d7:01:10:cb:7b:7c:82:63"
            ) and
            1570626662 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ef2d35f2ae82a767a16be582ab0d1ba0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Workstage Limited" and (
                pe.signatures[i].serial == "00:ef:2d:35:f2:ae:82:a7:67:a1:6b:e5:82:ab:0d:1b:a0" or
                pe.signatures[i].serial == "ef:2d:35:f2:ae:82:a7:67:a1:6b:e5:82:ab:0d:1b:a0"
            ) and
            1567123200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_039668034826df47e6207ec9daed57c3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CHOO FSP, LLC" and
            pe.signatures[i].serial == "03:96:68:03:48:26:df:47:e6:20:7e:c9:da:ed:57:c3" and
            1601424001 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07bb6a9d1c642c5973c16d5353b17ca4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MADAS d.o.o." and
            pe.signatures[i].serial == "07:bb:6a:9d:1c:64:2c:59:73:c1:6d:53:53:b1:7c:a4" and
            1601856001 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a1dc99e4d5264c45a5090f93242a30a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "K & D KOMPANI d.o.o." and
            pe.signatures[i].serial == "0a:1d:c9:9e:4d:52:64:c4:5a:50:90:f9:32:42:a3:0a" and
            1600905601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_018093cfad72cdf402eecbe18b33ec71 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FAT11 d.o.o." and 
            pe.signatures[i].serial == "01:80:93:cf:ad:72:cd:f4:02:ee:cb:e1:8b:33:ec:71" and
            1602000390 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_569e03988af60d80ce60728940850d9b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OORT inc." and (
                pe.signatures[i].serial == "00:56:9e:03:98:8a:f6:0d:80:ce:60:72:89:40:85:0d:9b" or
                pe.signatures[i].serial == "56:9e:03:98:8a:f6:0d:80:ce:60:72:89:40:85:0d:9b"
            ) and
            1601006510 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_418f6d959a8a0f82bef07ceba3603e52 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OORT inc." and (
                pe.signatures[i].serial == "00:41:8f:6d:95:9a:8a:0f:82:be:f0:7c:eb:a3:60:3e:52" or
                pe.signatures[i].serial == "41:8f:6d:95:9a:8a:0f:82:be:f0:7c:eb:a3:60:3e:52"
            ) and
            1601928240 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5378c5bbeba0d3309a35bb47f63037f7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OORT inc." and (
                pe.signatures[i].serial == "00:53:78:c5:bb:eb:a0:d3:30:9a:35:bb:47:f6:30:37:f7" or
                pe.signatures[i].serial == "53:78:c5:bb:eb:a0:d3:30:9a:35:bb:47:f6:30:37:f7"
            ) and
            1601427420 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0bab6a2aa84b495d9e554a4c42c0126d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NOSOV SP Z O O" and
            pe.signatures[i].serial == "0b:ab:6a:2a:a8:4b:49:5d:9e:55:4a:4c:42:c0:12:6d" and
            1597971600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6314001c3235cd59bcc3f5278c518804 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GIE-MUTUALISTE" and
            pe.signatures[i].serial == "63:14:00:1c:32:35:cd:59:bc:c3:f5:27:8c:51:88:04" and
            1600304400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0ed8ade5d73b73dade6943d557ff87e5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rumikon LLC" and
            pe.signatures[i].serial == "0e:d8:ad:e5:d7:3b:73:da:de:69:43:d5:57:ff:87:e5" and
            1597885200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0292c7d574132ba5c0441d1c7ffcb805 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TES LOGISTIKA d.o.o." and
            pe.signatures[i].serial == "02:92:c7:d5:74:13:2b:a5:c0:44:1d:1c:7f:fc:b8:05" and
            1602183720 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1f23f001458716d435cca1a55d660ec5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Ringen" and
            pe.signatures[i].serial == "1f:23:f0:01:45:87:16:d4:35:cc:a1:a5:5d:66:0e:c5" and
            1603176940 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6e0ccbdfb4777e10ea6221b90dc350c2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TRAUMALAB INTERNATIONAL APS" and
            pe.signatures[i].serial == "6e:0c:cb:df:b4:77:7e:10:ea:62:21:b9:0d:c3:50:c2" and
            1603046620 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0ed1847a2ae5d71def1e833fddd33d38 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SNAB-RESURS, OOO" and
            pe.signatures[i].serial == "0e:d1:84:7a:2a:e5:d7:1d:ef:1e:83:3f:dd:d3:3d:38" and
            1598662800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_97df46acb26b7c81a13cc467b47688c8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Information Civilized System Oy" and (
                pe.signatures[i].serial == "00:97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8" or
                pe.signatures[i].serial == "97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8"
            ) and
            1602636910 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_186d49fac34ce99775b8e7ffbf50679d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hairis LLC" and
            pe.signatures[i].serial == "18:6d:49:fa:c3:4c:e9:97:75:b8:e7:ff:bf:50:67:9d" and
            1602234590 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b1aea98bf0ce789b6c952310f14edde0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Absolut LLC" and (
                pe.signatures[i].serial == "00:b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0" or
                pe.signatures[i].serial == "b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0"
            ) and
            1602612570 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2dcd0699da08915dde6d044cb474157c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VENTE DE TOUT" and
            pe.signatures[i].serial == "2d:cd:06:99:da:08:91:5d:de:6d:04:4c:b4:74:15:7c" and
            1601830010 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4b03cabe6a0481f17a2dbeb9aefad425 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RASSVET, OOO" and
            pe.signatures[i].serial == "4b:03:ca:be:6a:04:81:f1:7a:2d:be:b9:ae:fa:d4:25" and
            1603230930 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_64cd303fa289790afa03c403e9240002 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MAITLAND TRIFECTA, INC." and 
            pe.signatures[i].serial == "64:cd:30:3f:a2:89:79:0a:fa:03:c4:03:e9:24:00:02" and
            1602723600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07cef66a71c35bc3aed6d100c6493863 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fubon Technologies Ltd" and
            pe.signatures[i].serial == "07:ce:f6:6a:71:c3:5b:c3:ae:d6:d1:00:c6:49:38:63" and
            1602740890 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_be77fe5c58b7a360add6a3fced4e8334 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Incar LLC" and (
                pe.signatures[i].serial == "00:be:77:fe:5c:58:b7:a3:60:ad:d6:a3:fc:ed:4e:83:34" or
                pe.signatures[i].serial == "be:77:fe:5c:58:b7:a3:60:ad:d6:a3:fc:ed:4e:83:34"
            ) and
            1602530730 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f097e59809ae2e771b7b9ae5fc3408d7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABEL RENOVATIONS, INC." and (
                pe.signatures[i].serial == "00:f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7" or
                pe.signatures[i].serial == "f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7"
            ) and
            1602542033 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0cf1ed2a6ff4bee621efdf725ea174b7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LEVEL LIST SP Z O O" and
            pe.signatures[i].serial == "0c:f1:ed:2a:6f:f4:be:e6:21:ef:df:72:5e:a1:74:b7" and
            1603036100 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1249aa2ada4967969b71ce63bf187c38 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Umbrella LLC" and
            pe.signatures[i].serial == "12:49:aa:2a:da:49:67:96:9b:71:ce:63:bf:18:7c:38" and
            1599181200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d59a05955a4a421500f9561ce983aac4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Olymp LLC" and (
                pe.signatures[i].serial == "00:d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4" or
                pe.signatures[i].serial == "d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4"
            ) and
            1601895290 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_539015999e304a5952985a994f9c3a53 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Service lab LLC" and
            pe.signatures[i].serial == "53:90:15:99:9e:30:4a:59:52:98:5a:99:4f:9c:3a:53" and
            1599181200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0b1926a5e8ae50a0efa504f005f93869 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nordkod LLC" and
            pe.signatures[i].serial == "0b:19:26:a5:e8:ae:50:a0:ef:a5:04:f0:05:f9:38:69" and
            1600650000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a23b660e7322e54d7bd0e5acc890966 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ARTBUD RADOM SP Z O O" and
            pe.signatures[i].serial == "0a:23:b6:60:e7:32:2e:54:d7:bd:0e:5a:cc:89:09:66" and
            1601254800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6cfa5050c819c4acbb8fa75979688dff {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Elite Web Development Ltd." and (
                pe.signatures[i].serial == "00:6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff" or
                pe.signatures[i].serial == "6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff"
            ) and
            1600176940 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_044e05bb1a01a1cbb50cfb6cd24e5d6b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MUSTER PLUS SP Z O O" and
            pe.signatures[i].serial == "04:4e:05:bb:1a:01:a1:cb:b5:0c:fb:6c:d2:4e:5d:6b" and
            1601427600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b7f19b13de9bee8a52ff365ced6f67fa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALEXIS SECURITY GROUP, LLC" and (
                pe.signatures[i].serial == "00:b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa" or
                pe.signatures[i].serial == "b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa"
            ) and
            1574914319 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b61b8e71514059adc604da05c283e514 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APP DIVISION ApS" and (
                pe.signatures[i].serial == "00:b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14" or
                pe.signatures[i].serial == "b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14"
            ) and
            1603328400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ece6cbf67dc41635a5e5d075f286af23 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THRANE AGENTUR ApS" and (
                pe.signatures[i].serial == "00:ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23" or
                pe.signatures[i].serial == "ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23"
            ) and
            1603369254 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_014a98d697b44f43ded21f18eb6ad0ba {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hillcoe Software Inc." and
            pe.signatures[i].serial == "01:4a:98:d6:97:b4:4f:43:de:d2:1f:18:eb:6a:d0:ba" and
            1605364760 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_063a7d09107eddd8aa1f733634c6591b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Smart Line Logistics" and
            pe.signatures[i].serial == "06:3a:7d:09:10:7e:dd:d8:aa:1f:73:36:34:c6:59:1b" and
            1605712706 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1e74cfe7de8c5f57840a61034414ca9f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Insta Software Solution Inc." and (
                pe.signatures[i].serial == "00:1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f" or
                pe.signatures[i].serial == "1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f"
            ) and
            1601733106 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_75cf729f8a740bbdef183a1c4d86a02f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Umbor LLC" and
            pe.signatures[i].serial == "75:cf:72:9f:8a:74:0b:bd:ef:18:3a:1c:4d:86:a0:2f" and
            1604223894 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2f64677254d3844efdac2922123d05d1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ORGANICUP ApS" and
            pe.signatures[i].serial == "2f:64:67:72:54:d3:84:4e:fd:ac:29:22:12:3d:05:d1" and
            1605640092 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_32fbf8cfa43dca3f85efabe96dfefa49 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Foxstyle LLC" and
            pe.signatures[i].serial == "32:fb:f8:cf:a4:3d:ca:3f:85:ef:ab:e9:6d:fe:fa:49" and
            1598255906 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ef9d0cf071d463cd63d13083046a7b8d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rubin LLC" and (
                pe.signatures[i].serial == "00:ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d" or
                pe.signatures[i].serial == "ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d"
            ) and
            1605358307 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_115cf1353a0e33e19099a4867a4c750a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "212 NY Gifts, Inc." and (
                pe.signatures[i].serial == "00:11:5c:f1:35:3a:0e:33:e1:90:99:a4:86:7a:4c:75:0a" or
                pe.signatures[i].serial == "11:5c:f1:35:3a:0e:33:e1:90:99:a4:86:7a:4c:75:0a"
            ) and
            1605515909 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5cf3778bb11115a884e192a7cb807599 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLOMATIC d.o.o." and (
                pe.signatures[i].serial == "00:5c:f3:77:8b:b1:11:15:a8:84:e1:92:a7:cb:80:75:99" or
                pe.signatures[i].serial == "5c:f3:77:8b:b1:11:15:a8:84:e1:92:a7:cb:80:75:99"
            ) and
            1605006199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_82cb93593b658100cdd7a00c874287f2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sportsonline24 B.V." and (
                pe.signatures[i].serial == "00:82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2" or
                pe.signatures[i].serial == "82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2"
            ) and
            1605117874 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9a8bcfd05f86b15d0c99f50cf414bd00 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AI Software a.s." and (
                pe.signatures[i].serial == "00:9a:8b:cf:d0:5f:86:b1:5d:0c:99:f5:0c:f4:14:bd:00" or
                pe.signatures[i].serial == "9a:8b:cf:d0:5f:86:b1:5d:0c:99:f5:0c:f4:14:bd:00"
            ) and
            1592442000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_95e5793f2abe0b4ec9be54fd24f76ae5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kommservice LLC" and (
                pe.signatures[i].serial == "00:95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5" or
                pe.signatures[i].serial == "95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5"
            ) and
            1604933746 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_133565779808c3b79d8e3f70a9c3ffac {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Istok" and
            pe.signatures[i].serial == "13:35:65:77:98:08:c3:b7:9d:8e:3f:70:a9:c3:ff:ac" and
            1605019819 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7e0ccda0ef37acef6c2ebe4538627e5c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Orangetree B.V." and (
                pe.signatures[i].serial == "00:7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c" or
                pe.signatures[i].serial == "7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c"
            ) and
            1606159604 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bad35fd70025d46c56b89e32b1a3954c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fort LLC" and (
                pe.signatures[i].serial == "00:ba:d3:5f:d7:00:25:d4:6c:56:b8:9e:32:b1:a3:95:4c" or
                pe.signatures[i].serial == "ba:d3:5f:d7:00:25:d4:6c:56:b8:9e:32:b1:a3:95:4c"
            ) and
            1604937337 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7b91468122273aa32b7cfc80c331ea13 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO KBI" and
            pe.signatures[i].serial == "7b:91:46:81:22:27:3a:a3:2b:7c:fc:80:c3:31:ea:13" and
            1586942863 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3e267b5d14cdf1f645c1ec545cec3aee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO KBI" and
            pe.signatures[i].serial == "3e:26:7b:5d:14:cd:f1:f6:45:c1:ec:54:5c:ec:3a:ee" and
            1579825892 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ae6d3c0269ef6497e14379c51a8507ba {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VELES PROPERTIES LIMITED" and (
                pe.signatures[i].serial == "00:ae:6d:3c:02:69:ef:64:97:e1:43:79:c5:1a:85:07:ba" or
                pe.signatures[i].serial == "ae:6d:3c:02:69:ef:64:97:e1:43:79:c5:1a:85:07:ba"
            ) and
            1578566034 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fd8c468cc1b45c9cfb41cbd8c835cc9e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pivo ZLoun s.r.o." and (
                pe.signatures[i].serial == "00:fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e" or
                pe.signatures[i].serial == "fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e"
            ) and
            1604019600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7c061baa3118327255161f6a7fa4e21d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "YUTAKS, OOO" and (
                pe.signatures[i].serial == "00:7c:06:1b:aa:31:18:32:72:55:16:1f:6a:7f:a4:e2:1d" or
                pe.signatures[i].serial == "7c:06:1b:aa:31:18:32:72:55:16:1f:6a:7f:a4:e2:1d"
            ) and
            1599611338 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04332c16724ffeda5868d22af56aea43 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bespoke Software Solutions Limited" and
            pe.signatures[i].serial == "04:33:2c:16:72:4f:fe:da:58:68:d2:2a:f5:6a:ea:43" and
            1597971601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_030012f134e64347669f3256c7d050c5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Futumarket LLC" and
            pe.signatures[i].serial == "03:00:12:f1:34:e6:43:47:66:9f:32:56:c7:d0:50:c5" and
            1604036657 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fa3dcac19b884b44ef4f81541184d6b0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unicom Ltd" and (
                pe.signatures[i].serial == "00:fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0" or
                pe.signatures[i].serial == "fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0"
            ) and
            1603958571 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0e6f4cb8b06e01c3bd296ace3a95f814 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EVATON, s.r.o." and
            pe.signatures[i].serial == "0e:6f:4c:b8:b0:6e:01:c3:bd:29:6a:ce:3a:95:f8:14" and
            1603957781 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_085b70224253486624fc36fa658a1e32 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Best Fud, OOO" and
            pe.signatures[i].serial == "08:5b:70:22:42:53:48:66:24:fc:36:fa:65:8a:1e:32" and
            1597971601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_51cd5393514f7ace2b407c3dbfb09d8d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APPI CZ a.s" and
            pe.signatures[i].serial == "51:cd:53:93:51:4f:7a:ce:2b:40:7c:3d:bf:b0:9d:8d" and
            1605299467 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b72179c027b9037ee220e81ab18fe56d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Planeta, TOV" and (
                pe.signatures[i].serial == "00:b7:21:79:c0:27:b9:03:7e:e2:20:e8:1a:b1:8f:e5:6d" or
                pe.signatures[i].serial == "b7:21:79:c0:27:b9:03:7e:e2:20:e8:1a:b1:8f:e5:6d"
            ) and
            1603381300 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07b74c70c4aa092648b7f0d1a8a3a28f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rad-Grad D.O.O." and
            pe.signatures[i].serial == "07:b7:4c:70:c4:aa:09:26:48:b7:f0:d1:a8:a3:a2:8f" and
            1603240965 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4c8def294478b7d59ee95c61fae3d965 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DREAM SECURITY USA INC" and
            pe.signatures[i].serial == "4c:8d:ef:29:44:78:b7:d5:9e:e9:5c:61:fa:e3:d9:65" and
            1592961292 <= pe.signatures[i].not_after
        )
}
