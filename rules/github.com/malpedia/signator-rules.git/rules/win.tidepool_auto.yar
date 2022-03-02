rule win_tidepool_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.tidepool."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tidepool"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 5b 8b8d00030000 33cd e8???????? 81c504030000 }
            // n = 5, score = 1000
            //   5b                   | pop                 ebx
            //   8b8d00030000         | mov                 ecx, dword ptr [ebp + 0x300]
            //   33cd                 | xor                 ecx, ebp
            //   e8????????           |                     
            //   81c504030000         | add                 ebp, 0x304

        $sequence_1 = { 5e c20400 80790800 c701???????? }
            // n = 4, score = 1000
            //   5e                   | pop                 esi
            //   c20400               | ret                 4
            //   80790800             | cmp                 byte ptr [ecx + 8], 0
            //   c701????????         |                     

        $sequence_2 = { 6a00 50 8b08 ff91a4000000 }
            // n = 4, score = 1000
            //   6a00                 | push                0
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff91a4000000         | call                dword ptr [ecx + 0xa4]

        $sequence_3 = { 64890d00000000 59 5f 5e 5b 8b8d00030000 }
            // n = 6, score = 1000
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8b8d00030000         | mov                 ecx, dword ptr [ebp + 0x300]

        $sequence_4 = { 83e906 51 83c006 50 6a02 }
            // n = 5, score = 900
            //   83e906               | sub                 ecx, 6
            //   51                   | push                ecx
            //   83c006               | add                 eax, 6
            //   50                   | push                eax
            //   6a02                 | push                2

        $sequence_5 = { e8???????? 83c40c 803d????????37 7518 }
            // n = 4, score = 900
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   803d????????37       |                     
            //   7518                 | jne                 0x1a

        $sequence_6 = { 33db 53 6a02 8bf1 e8???????? }
            // n = 5, score = 900
            //   33db                 | xor                 ebx, ebx
            //   53                   | push                ebx
            //   6a02                 | push                2
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     

        $sequence_7 = { 6800000040 8d4500 50 ff15???????? }
            // n = 4, score = 900
            //   6800000040           | push                0x40000000
            //   8d4500               | lea                 eax, dword ptr [ebp]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_8 = { b8???????? b900000400 c60000 40 49 }
            // n = 5, score = 800
            //   b8????????           |                     
            //   b900000400           | mov                 ecx, 0x40000
            //   c60000               | mov                 byte ptr [eax], 0
            //   40                   | inc                 eax
            //   49                   | dec                 ecx

        $sequence_9 = { 52 50 8b08 ff91f8000000 }
            // n = 4, score = 800
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff91f8000000         | call                dword ptr [ecx + 0xf8]

        $sequence_10 = { 52 50 ff91d0000000 33ff 8b4654 }
            // n = 5, score = 800
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff91d0000000         | call                dword ptr [ecx + 0xd0]
            //   33ff                 | xor                 edi, edi
            //   8b4654               | mov                 eax, dword ptr [esi + 0x54]

        $sequence_11 = { 8b4654 50 8b08 ff5138 }
            // n = 4, score = 800
            //   8b4654               | mov                 eax, dword ptr [esi + 0x54]
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5138               | call                dword ptr [ecx + 0x38]

        $sequence_12 = { c3 ff25???????? 51 8d4c2404 }
            // n = 4, score = 800
            //   c3                   | ret                 
            //   ff25????????         |                     
            //   51                   | push                ecx
            //   8d4c2404             | lea                 ecx, dword ptr [esp + 4]

        $sequence_13 = { 8b08 ff91a4000000 8b4654 6a01 }
            // n = 4, score = 800
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff91a4000000         | call                dword ptr [ecx + 0xa4]
            //   8b4654               | mov                 eax, dword ptr [esi + 0x54]
            //   6a01                 | push                1

        $sequence_14 = { 681f000200 56 68???????? 6801000080 }
            // n = 4, score = 800
            //   681f000200           | push                0x2001f
            //   56                   | push                esi
            //   68????????           |                     
            //   6801000080           | push                0x80000001

        $sequence_15 = { 6810270000 ff15???????? 8b45ec 8b08 }
            // n = 4, score = 800
            //   6810270000           | push                0x2710
            //   ff15????????         |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_16 = { 6802020000 ff15???????? 68???????? ff15???????? 8bf8 85ff }
            // n = 6, score = 800
            //   6802020000           | push                0x202
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi

        $sequence_17 = { e8???????? 68???????? 68???????? 68???????? 8d4500 }
            // n = 5, score = 800
            //   e8????????           |                     
            //   68????????           |                     
            //   68????????           |                     
            //   68????????           |                     
            //   8d4500               | lea                 eax, dword ptr [ebp]

        $sequence_18 = { c3 56 8bf1 e8???????? 8b4654 }
            // n = 5, score = 800
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   8b4654               | mov                 eax, dword ptr [esi + 0x54]

        $sequence_19 = { 8b4c2424 3bc1 0f8d78020000 2bc8 }
            // n = 4, score = 600
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   3bc1                 | cmp                 eax, ecx
            //   0f8d78020000         | jge                 0x27e
            //   2bc8                 | sub                 ecx, eax

        $sequence_20 = { e8???????? 68???????? 8d8500040000 50 }
            // n = 4, score = 600
            //   e8????????           |                     
            //   68????????           |                     
            //   8d8500040000         | lea                 eax, dword ptr [ebp + 0x400]
            //   50                   | push                eax

        $sequence_21 = { ff75ec ff15???????? 8b35???????? 6a04 }
            // n = 4, score = 400
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   6a04                 | push                4

        $sequence_22 = { 894318 a1???????? 59 89431c 59 }
            // n = 5, score = 200
            //   894318               | mov                 dword ptr [ebx + 0x18], eax
            //   a1????????           |                     
            //   59                   | pop                 ecx
            //   89431c               | mov                 dword ptr [ebx + 0x1c], eax
            //   59                   | pop                 ecx

        $sequence_23 = { 53 6a00 50 89450c }
            // n = 4, score = 200
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   50                   | push                eax
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax

        $sequence_24 = { 83c40c 83c018 897df4 8945f8 }
            // n = 4, score = 200
            //   83c40c               | add                 esp, 0xc
            //   83c018               | add                 eax, 0x18
            //   897df4               | mov                 dword ptr [ebp - 0xc], edi
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_25 = { ffd7 8d45d8 56 50 8d45f8 50 8d45ec }
            // n = 7, score = 200
            //   ffd7                 | call                edi
            //   8d45d8               | lea                 eax, dword ptr [ebp - 0x28]
            //   56                   | push                esi
            //   50                   | push                eax
            //   8d45f8               | lea                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   8d45ec               | lea                 eax, dword ptr [ebp - 0x14]

        $sequence_26 = { ffd6 8325????????00 83c40c 5f }
            // n = 4, score = 200
            //   ffd6                 | call                esi
            //   8325????????00       |                     
            //   83c40c               | add                 esp, 0xc
            //   5f                   | pop                 edi

        $sequence_27 = { 8b00 894508 ffd6 85c0 }
            // n = 4, score = 200
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 1998848
}