rule masslogger_stealer {

    meta:

        description = "Rule to detect unpacked MassLogger stealer"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-07-02"
        rule_version = "v1"
        malware_type = "stealer"
        malware_family = "Stealer:W32/MassLogger"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://urlhaus.abuse.ch/browse/signature/MassLogger/"
        hash = "343873155b6950386f7d9bcd8d2b2e81088521aedf8ff1333d20229426d8145c"

    strings:

        $pattern_0 = { 6437 3e2585829c88 ec ec 1bc8 }
        $pattern_1 = { d7 b9513e1ba7 195ab6 e6df 7e2a 5a b6cc }
        $pattern_2 = { 80aee281aae280 8ee2 808ce2808ee2808e e280 ae 00436f 6e }
        $pattern_3 = { 6d e586 4c 40 }
        $pattern_4 = { e281 ab e280 8ee2 80aee281aae280 8ee2 }
        $pattern_5 = { 6c 69636b65644576 656e 7441 7267 7300 }
        $pattern_6 = { 6e 7e81 d86aaf 61 93 7c2b 832b62 }
        $pattern_7 = { 8b1c87 e7ed 24a2 3218 73df 53 }
        $pattern_8 = { ee 9a357f9a475399 3188eef97d50 3f ef c9 }             
        $pattern_9 = { 44 a2???????? 92 7526 42 208fb5ca7050 }
        $pattern_10 = { f2bbafb0d5f8 d524 0d48c906ba 7977 5d }
        $pattern_11 = { 748f 46 4e 49 2af2 ee 9a357f9a475399 }
        $pattern_12 = { 237ddb e200 95 46 99 37 }            
        $pattern_13 = { d9ae1d19ec3b 01db c5615c ec }
        $pattern_14 = { 304a8a e2f4 bde7a84f79 c038d3 197ceae6 }
        $pattern_15 = { 291f ff84c3bd55d8dc f331f2 1a3a 9c 7d78 }
        $pattern_16 = { 3f 7af1 77a2 24ae 7ff3 }
        $pattern_17 = { d1655d 7236 3873c1 b59e }
        $pattern_18 = { 2aff 95 55 28ff 94 53 }
        $pattern_19 = { e6b1 43 08d2 ef 43 3c38 }
        $pattern_20 = { 6964427275736800 43 6f 6c 6f 7200 e281 }
        $pattern_21 = { 37 005400a7 877f08 54 00e1 875303 5c }
        $pattern_22 = { 6a45 e42c d3ba76c4f058 ce 3037 }
        $pattern_23 = { b59e 59 f1 f1 }        
        $pattern_24 = { 7988 cd09 91 0099664e0391 008288490061 008c88d3099900 }
        $pattern_25 = { 1e e3c2 00ff 698876be8fb365b13eb7 45 }
        $pattern_26 = { 3d4c9deadf 57 ddeb 97 }
        $pattern_27 = { e280 8ee2 808ee281aee280 8ee2 81ace281ace280ade280ab e281 }
        $pattern_28 = { 4d 9c 8e5753 32414f d28a7173e2c4 7ee4 d9ae1d19ec3b }
        $pattern_29 = { 7472 69704d656e755f 53 61 }          
        $pattern_30 = { 79bc fa ad 49 }
        $pattern_31 = { 875303 5c 00140a 37 005c00a7 }
        $pattern_32 = { 7265 5f 43 6c 69636b00746f6f 6c 53 }
        $pattern_33 = { 36e633 2b2b 3673d1 d480 124d2d }
        $pattern_34 = { 19b3e7ab29db 51 e1f3 dd3a 266f b884c4b53b }
        $pattern_35 = { 7467 43 f332d2 84bf3df2e66b 4a ba5a20d9f5 3dbf2a3753 }
        $pattern_36 = { f271f3 8877f7 a8e5 6437 3e2585829c88 }
        $pattern_37 = { ce 84604c 3f 8cc6 56 bf165fdec5 4a }
        $pattern_38 = { ad 49 a2???????? 4c e15b 8b1c87 }
        $pattern_39 = { 3400 b687 bc083c00cd 87ce 083400 }


    condition:

        7 of them and filesize < 3834880
}
