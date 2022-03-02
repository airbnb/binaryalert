rule win_oceansalt_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.oceansalt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oceansalt"
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
        $sequence_0 = { 57 6a00 6a02 c785ccfdffff28010000 e8???????? 8d8dccfdffff 51 }
            // n = 7, score = 300
            //   57                   | push                edi
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   c785ccfdffff28010000     | mov    dword ptr [ebp - 0x234], 0x128
            //   e8????????           |                     
            //   8d8dccfdffff         | lea                 ecx, dword ptr [ebp - 0x234]
            //   51                   | push                ecx

        $sequence_1 = { 6a02 6a00 6a02 6800000040 8d8df8f9ffff 51 }
            // n = 6, score = 300
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   6800000040           | push                0x40000000
            //   8d8df8f9ffff         | lea                 ecx, dword ptr [ebp - 0x608]
            //   51                   | push                ecx

        $sequence_2 = { 33c5 8945fc 8d856cfeffff 50 6801010000 ff15???????? 85c0 }
            // n = 7, score = 300
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d856cfeffff         | lea                 eax, dword ptr [ebp - 0x194]
            //   50                   | push                eax
            //   6801010000           | push                0x101
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_3 = { ff15???????? 8b550c 2bd0 8a08 880c02 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   2bd0                 | sub                 edx, eax
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   880c02               | mov                 byte ptr [edx + eax], cl

        $sequence_4 = { 5d c3 57 ff15???????? 6a00 6a09 }
            // n = 6, score = 300
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   57                   | push                edi
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a09                 | push                9

        $sequence_5 = { 58 5d c3 8b04cd2cf04000 }
            // n = 4, score = 300
            //   58                   | pop                 eax
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b04cd2cf04000       | mov                 eax, dword ptr [ecx*8 + 0x40f02c]

        $sequence_6 = { 8b4d08 56 8d450c 50 51 8d95fcfbffff 6800020000 }
            // n = 7, score = 300
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   8d450c               | lea                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8d95fcfbffff         | lea                 edx, dword ptr [ebp - 0x404]
            //   6800020000           | push                0x200

        $sequence_7 = { 8d95fcfbffff 6800020000 52 e8???????? 83c410 8d85ecfbffff 50 }
            // n = 7, score = 300
            //   8d95fcfbffff         | lea                 edx, dword ptr [ebp - 0x404]
            //   6800020000           | push                0x200
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8d85ecfbffff         | lea                 eax, dword ptr [ebp - 0x414]
            //   50                   | push                eax

        $sequence_8 = { 4b8b84f1a0470100 4c895c3040 4b8b84f1a0470100 498bd5 }
            // n = 4, score = 100
            //   4b8b84f1a0470100     | jmp                 0x3d
            //   4c895c3040           | dec                 ebx
            //   4b8b84f1a0470100     | mov                 eax, dword ptr [ecx + esi*8 + 0x147a0]
            //   498bd5               | dec                 esp

        $sequence_9 = { eb22 4b8b84f0a0470100 f644300840 7507 }
            // n = 4, score = 100
            //   eb22                 | dec                 ebx
            //   4b8b84f0a0470100     | mov                 ecx, dword ptr [eax + esi*8 + 0x147a0]
            //   f644300840           | mov                 byte ptr [ecx + esi + 9], al
            //   7507                 | mov                 al, byte ptr [esp + 0xb9]

        $sequence_10 = { e8???????? eb4e 488b0d???????? 488d542434 e8???????? eb3b 488b0d???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   eb4e                 | jmp                 0x50
            //   488b0d????????       |                     
            //   488d542434           | dec                 eax
            //   e8????????           |                     
            //   eb3b                 | lea                 edx, dword ptr [esp + 0x34]
            //   488b0d????????       |                     

        $sequence_11 = { 33d2 41b804020000 e8???????? 488db4248c000000 488d3db2ce0000 b902000000 }
            // n = 6, score = 100
            //   33d2                 | mov                 dword ptr [eax + esi + 0x40], ebx
            //   41b804020000         | dec                 ebx
            //   e8????????           |                     
            //   488db4248c000000     | mov                 eax, dword ptr [ecx + esi*8 + 0x147a0]
            //   488d3db2ce0000       | dec                 ecx
            //   b902000000           | mov                 edx, ebp

        $sequence_12 = { e8???????? 488d0d90c80000 e8???????? 48ffc0 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   488d0d90c80000       | dec                 ebx
            //   e8????????           |                     
            //   48ffc0               | mov                 ecx, dword ptr [eax + esi*8 + 0x147a0]

        $sequence_13 = { 8a8424b8000000 4b8b8cf0a0470100 88443109 8a8424b9000000 4b8b8cf0a0470100 88443139 }
            // n = 6, score = 100
            //   8a8424b8000000       | lea                 esi, dword ptr [esp + 0x8c]
            //   4b8b8cf0a0470100     | dec                 eax
            //   88443109             | lea                 edi, dword ptr [0xceb2]
            //   8a8424b9000000       | mov                 ecx, 2
            //   4b8b8cf0a0470100     | dec                 eax
            //   88443139             | lea                 edi, dword ptr [0xce87]

        $sequence_14 = { 488bcb c784243401000000000000 ff15???????? 488b8c2470020000 4833cc }
            // n = 5, score = 100
            //   488bcb               | mov                 ecx, 3
            //   c784243401000000000000     | repe cmpsb    byte ptr [esi], byte ptr es:[edi]
            //   ff15????????         |                     
            //   488b8c2470020000     | je                  0x16b
            //   4833cc               | mov                 al, byte ptr [esp + 0xb8]

        $sequence_15 = { 488d3d87ce0000 b903000000 f3a6 0f8463010000 }
            // n = 4, score = 100
            //   488d3d87ce0000       | xor                 edx, edx
            //   b903000000           | inc                 ecx
            //   f3a6                 | mov                 eax, 0x204
            //   0f8463010000         | dec                 eax

    condition:
        7 of them and filesize < 212992
}