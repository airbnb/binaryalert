rule MALW_thiefquest
{
    meta:
    
        description = "Rule to detect the Evilquest/ThiefQuest malware"
        author = "McAfee ATR Team"
        date = "2020-07-09"
        rule_version = "v1"
        malware_type = "keylogger, backdoor, ransomware"
        actor_type = "Cybercrime"
        malware_family = "Ransom:OSX/ThiefQuest"
        reference = "https://www.bleepingcomputer.com/news/security/thiefquest-ransomware-is-a-file-stealing-mac-wiper-in-disguise/"
        hash = "5a024ffabefa6082031dccdb1e74a7fec9f60f257cd0b1ab0f698ba2a5baca6b"
    
    strings:

        $pattern_0 = { 01c1 48 83c102 48 }
        $pattern_1 = { 8c1471 80c1c1 98 1c8c }
        $pattern_2 = { d8974f0dc89a 9f c9 9adf70cd595390 }
        $pattern_3 = { d897c56f028c 2393a0a42e92 8ea2c27affc2 f8 }
        $pattern_4 = { 477006 baa6a1cb82 ae f9 e8???????? d8a32bd0d519 }
        $pattern_5 = { d898ab5c757b 2f f26f 5d }
        $pattern_6 = { bc007a846b 2b54adaf 93 35eddf38e6 cdd0 b246 }
        $pattern_7 = { ae 49b00e 01d1 45da611b 44839db656691674 }
        $pattern_8 = { 01c1 48 83c101 48 }
        $pattern_9 = { 6be3c6 5c 99 ae ed bf370e2f47 }
        $pattern_10 = { fd d7 43bd18fd6f06 7937 fa }
        $pattern_11 = { 01c2 48 83c201 bf01000000 }
        $pattern_12 = { d89825ed4469 29f1 5c e12d }
        $pattern_13 = { d8992062f7f9 73ff 90 085fc6 }
        $pattern_14 = { 01c1 6689ca 668995cefeffff e9???????? }
        $pattern_15 = { 01c1 41 89c8 44 }
        $pattern_16 = { d89935c487a7 bcdffa587c be6cadbb3c 185fc4 }
        $pattern_17 = { 01c1 48 8b75a8 48 }
        $pattern_18 = { 0000 48 8945f8 e9???????? }
        $pattern_19 = { d89959d6472d a2???????? 3525c7eec9 95 }
        $pattern_20 = { 01c2 48 83c203 bf01000000 }
        $pattern_21 = { 4a7888 ab 23e7 cf 11f3 }
        $pattern_22 = { d8982fbf222d 49 92 1d25b42bba }
        $pattern_23 = { e2d7 8437 6b4696d9 92 9d a6 }
   
    condition:

        7 of them and
        filesize < 124322606
}
