rule win_rifdoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.rifdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rifdoor"
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
        $sequence_0 = { 895c2414 e8???????? 8b4c2414 8be8 }
            // n = 4, score = 200
            //   895c2414             | mov                 dword ptr [esp + 0x14], ebx
            //   e8????????           |                     
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8be8                 | mov                 ebp, eax

        $sequence_1 = { 8b08 8d542420 52 8d542414 52 }
            // n = 5, score = 200
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8d542420             | lea                 edx, dword ptr [esp + 0x20]
            //   52                   | push                edx
            //   8d542414             | lea                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx

        $sequence_2 = { 89942480000000 53 8d942494000000 52 }
            // n = 4, score = 200
            //   89942480000000       | mov                 dword ptr [esp + 0x80], edx
            //   53                   | push                ebx
            //   8d942494000000       | lea                 edx, dword ptr [esp + 0x94]
            //   52                   | push                edx

        $sequence_3 = { 8d54240c 52 50 e8???????? 85c0 744e 56 }
            // n = 7, score = 200
            //   8d54240c             | lea                 edx, dword ptr [esp + 0xc]
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   744e                 | je                  0x50
            //   56                   | push                esi

        $sequence_4 = { 8d4c2410 a3???????? 51 8d4310 b9???????? 895c2414 e8???????? }
            // n = 7, score = 200
            //   8d4c2410             | lea                 ecx, dword ptr [esp + 0x10]
            //   a3????????           |                     
            //   51                   | push                ecx
            //   8d4310               | lea                 eax, dword ptr [ebx + 0x10]
            //   b9????????           |                     
            //   895c2414             | mov                 dword ptr [esp + 0x14], ebx
            //   e8????????           |                     

        $sequence_5 = { 59 ebcf 8bc6 c1f805 8b0485605d4100 83e61f }
            // n = 6, score = 200
            //   59                   | pop                 ecx
            //   ebcf                 | jmp                 0xffffffd1
            //   8bc6                 | mov                 eax, esi
            //   c1f805               | sar                 eax, 5
            //   8b0485605d4100       | mov                 eax, dword ptr [eax*4 + 0x415d60]
            //   83e61f               | and                 esi, 0x1f

        $sequence_6 = { 8b6c240c bb2a000000 754d 837e6400 7547 57 bf01000000 }
            // n = 7, score = 200
            //   8b6c240c             | mov                 ebp, dword ptr [esp + 0xc]
            //   bb2a000000           | mov                 ebx, 0x2a
            //   754d                 | jne                 0x4f
            //   837e6400             | cmp                 dword ptr [esi + 0x64], 0
            //   7547                 | jne                 0x49
            //   57                   | push                edi
            //   bf01000000           | mov                 edi, 1

        $sequence_7 = { a3???????? 52 b808000000 b9???????? }
            // n = 4, score = 200
            //   a3????????           |                     
            //   52                   | push                edx
            //   b808000000           | mov                 eax, 8
            //   b9????????           |                     

        $sequence_8 = { c1f805 8b0485605d4100 83e61f c1e606 59 }
            // n = 5, score = 200
            //   c1f805               | sar                 eax, 5
            //   8b0485605d4100       | mov                 eax, dword ptr [eax*4 + 0x415d60]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   59                   | pop                 ecx

        $sequence_9 = { 395c2414 7529 395c2418 7523 }
            // n = 4, score = 200
            //   395c2414             | cmp                 dword ptr [esp + 0x14], ebx
            //   7529                 | jne                 0x2b
            //   395c2418             | cmp                 dword ptr [esp + 0x18], ebx
            //   7523                 | jne                 0x25

    condition:
        7 of them and filesize < 212992
}