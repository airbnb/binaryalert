rule MAL_Klingon_Jun_2021_1 {
   meta:
        description = "Detect the Klingon RAT"
        author = "Arkbird_SOLG"
        reference = "https://www.intezer.com/blog/malware-analysis/klingon-rat-holding-on-for-dear-life/"
        date = "2021-06-19"
        hash1 = "44237e2de44a533751c0baace09cf83293572ae7c51cb4575e7267be289c6611"
        hash2 = "c98bb0649262277ec9dd16cf27f8b06042ff552535995f2bdd3355d2adeff801"
        hash3 = "e8eea442e148c81f116de31b4fc3d0aa725c5dbbbd840b446a3fb9793d0b9f26"
        tlp = "White"
        adversary = "-"
   strings:
        $seq1 = { 81 3a 70 72 6f 78 0f 85 [2] 00 00 80 7a 04 79 0f 84 [2] 00 00 48 83 f9 05 75 12 81 3a 73 68 65 6c 75 0a 80 7a 04 6c 0f 84 [2] 00 00 48 83 f9 06 75 14 81 3a 62 69 6e 61 75 0c 66 81 7a 04 72 79 0f 84 [2] 00 00 48 83 f9 03 0f 85 ?? 04 00 00 66 81 3a 63 6d 0f 85 [2] 00 00 80 7a 02 64 0f 84 [2] 00 00 48 83 f9 06 }
        $seq2 = { 48 8d 05 [3] 00 48 89 ?? 24 [1-4] 48 c7 84 24 ?? 00 00 00 ?? 00 00 00 48 8d 0d [3] 00 48 89 ?? 24 [0-4] 48 c7 ?? 24 } 
        $seq3 = { 48 8d 0d [3] 00 48 89 8c 24 ?? 00 00 00 48 8b 94 24 ?? 00 00 00 48 89 94 24 ?? 00 00 00 48 89 8c 24 ?? 00 00 00 48 8b 94 24 ?? 00 00 00 48 89 94 24 ?? 00 00 00 48 89 8c 24 ?? 00 00 00 48 89 84 24 ?? 00 00 00 48 8d 05 [3] 00 48 89 04 24 48 c7 44 24 08 08 00 00 00 48 8d 84 24 ?? 00 00 00 48 89 44 24 10 48 c7 44 24 18 03 00 00 00 48 c7 44 24 20 03 00 00 00 e8 [3] ff 48 8b 44 24 30 48 89 44 24 58 48 8b 4c 24 28 48 89 8c 24 ?? 00 00 00 }
   condition:
        uint16(0) == 0x5a4d and filesize > 300KB and all of ($seq*) 
}
