rule win_xtunnel_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.xtunnel."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xtunnel"
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
        $sequence_0 = { 8b11 83c202 52 e8???????? }
            // n = 4, score = 1200
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   83c202               | add                 edx, 2
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_1 = { e8???????? 99 b960000000 f7f9 }
            // n = 4, score = 1200
            //   e8????????           |                     
            //   99                   | cdq                 
            //   b960000000           | mov                 ecx, 0x60
            //   f7f9                 | idiv                ecx

        $sequence_2 = { 8b5658 39aa20010000 7468 813efffe0000 }
            // n = 4, score = 1100
            //   8b5658               | mov                 edx, dword ptr [esi + 0x58]
            //   39aa20010000         | cmp                 dword ptr [edx + 0x120], ebp
            //   7468                 | je                  0x6a
            //   813efffe0000         | cmp                 dword ptr [esi], 0xfeff

        $sequence_3 = { c7010c000000 5e 5d c3 6a00 }
            // n = 5, score = 1100
            //   c7010c000000         | mov                 dword ptr [ecx], 0xc
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   6a00                 | push                0

        $sequence_4 = { 8b4c2420 8b5638 55 51 }
            // n = 4, score = 1100
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   8b5638               | mov                 edx, dword ptr [esi + 0x38]
            //   55                   | push                ebp
            //   51                   | push                ecx

        $sequence_5 = { 8b5658 89ba74030000 8b4e58 898178030000 }
            // n = 4, score = 1100
            //   8b5658               | mov                 edx, dword ptr [esi + 0x58]
            //   89ba74030000         | mov                 dword ptr [edx + 0x374], edi
            //   8b4e58               | mov                 ecx, dword ptr [esi + 0x58]
            //   898178030000         | mov                 dword ptr [ecx + 0x378], eax

        $sequence_6 = { 8b5658 898268010000 8b7e58 8b542430 }
            // n = 4, score = 1100
            //   8b5658               | mov                 edx, dword ptr [esi + 0x58]
            //   898268010000         | mov                 dword ptr [edx + 0x168], eax
            //   8b7e58               | mov                 edi, dword ptr [esi + 0x58]
            //   8b542430             | mov                 edx, dword ptr [esp + 0x30]

        $sequence_7 = { 8b4c2420 8b542424 56 50 51 8b4c2434 }
            // n = 6, score = 1100
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   8b542424             | mov                 edx, dword ptr [esp + 0x24]
            //   56                   | push                esi
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8b4c2434             | mov                 ecx, dword ptr [esp + 0x34]

        $sequence_8 = { 8b542434 8b74243c 8b5c2414 52 }
            // n = 4, score = 1100
            //   8b542434             | mov                 edx, dword ptr [esp + 0x34]
            //   8b74243c             | mov                 esi, dword ptr [esp + 0x3c]
            //   8b5c2414             | mov                 ebx, dword ptr [esp + 0x14]
            //   52                   | push                edx

        $sequence_9 = { 8b5654 51 33db 52 894e60 897c2428 }
            // n = 6, score = 1100
            //   8b5654               | mov                 edx, dword ptr [esi + 0x54]
            //   51                   | push                ecx
            //   33db                 | xor                 ebx, ebx
            //   52                   | push                edx
            //   894e60               | mov                 dword ptr [esi + 0x60], ecx
            //   897c2428             | mov                 dword ptr [esp + 0x28], edi

        $sequence_10 = { 8b5658 56 89aa80010000 e8???????? 83c404 85c0 0f85effbffff }
            // n = 7, score = 1100
            //   8b5658               | mov                 edx, dword ptr [esi + 0x58]
            //   56                   | push                esi
            //   89aa80010000         | mov                 dword ptr [edx + 0x180], ebp
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   0f85effbffff         | jne                 0xfffffbf5

        $sequence_11 = { 50 ff15???????? 8b4b10 0fb71479 8b4b04 }
            // n = 5, score = 1000
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4b10               | mov                 ecx, dword ptr [ebx + 0x10]
            //   0fb71479             | movzx               edx, word ptr [ecx + edi*2]
            //   8b4b04               | mov                 ecx, dword ptr [ebx + 4]

        $sequence_12 = { 740a 8b450c e8???????? 8bd8 8b7d08 0fb7f6 c745fcffffffff }
            // n = 7, score = 1000
            //   740a                 | je                  0xc
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   0fb7f6               | movzx               esi, si
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff

        $sequence_13 = { 7409 50 e8???????? 83c404 897710 897714 897718 }
            // n = 7, score = 1000
            //   7409                 | je                  0xb
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   897710               | mov                 dword ptr [edi + 0x10], esi
            //   897714               | mov                 dword ptr [edi + 0x14], esi
            //   897718               | mov                 dword ptr [edi + 0x18], esi

        $sequence_14 = { 53 e8???????? 8d5f30 83c404 }
            // n = 4, score = 1000
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8d5f30               | lea                 ebx, dword ptr [edi + 0x30]
            //   83c404               | add                 esp, 4

        $sequence_15 = { 895f04 895f08 895f0c 895f10 c645fc06 }
            // n = 5, score = 1000
            //   895f04               | mov                 dword ptr [edi + 4], ebx
            //   895f08               | mov                 dword ptr [edi + 8], ebx
            //   895f0c               | mov                 dword ptr [edi + 0xc], ebx
            //   895f10               | mov                 dword ptr [edi + 0x10], ebx
            //   c645fc06             | mov                 byte ptr [ebp - 4], 6

        $sequence_16 = { 5b 8be5 5d c20800 8b45f0 8b4df4 }
            // n = 6, score = 1000
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_17 = { 8d4750 8d550c 89750c e8???????? 8918 }
            // n = 5, score = 1000
            //   8d4750               | lea                 eax, dword ptr [edi + 0x50]
            //   8d550c               | lea                 edx, dword ptr [ebp + 0xc]
            //   89750c               | mov                 dword ptr [ebp + 0xc], esi
            //   e8????????           |                     
            //   8918                 | mov                 dword ptr [eax], ebx

        $sequence_18 = { 83c404 895dec c645fc0b 8b4304 8b08 }
            // n = 5, score = 1000
            //   83c404               | add                 esp, 4
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   c645fc0b             | mov                 byte ptr [ebp - 4], 0xb
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_19 = { 8945b0 8b45b4 50 6a00 }
            // n = 4, score = 400
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_20 = { e8???????? 83c404 8945b0 8b45b4 }
            // n = 4, score = 400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]

        $sequence_21 = { c685c4f9ffffa8 c685c5f9ffff6d c685c6f9ffff81 c685c7f9ffffc2 }
            // n = 4, score = 300
            //   c685c4f9ffffa8       | mov                 byte ptr [ebp - 0x63c], 0xa8
            //   c685c5f9ffff6d       | mov                 byte ptr [ebp - 0x63b], 0x6d
            //   c685c6f9ffff81       | mov                 byte ptr [ebp - 0x63a], 0x81
            //   c685c7f9ffffc2       | mov                 byte ptr [ebp - 0x639], 0xc2

        $sequence_22 = { c685c4fbffff04 c685c5fbffffbb c685c6fbffffe6 c685c7fbffff36 }
            // n = 4, score = 300
            //   c685c4fbffff04       | mov                 byte ptr [ebp - 0x43c], 4
            //   c685c5fbffffbb       | mov                 byte ptr [ebp - 0x43b], 0xbb
            //   c685c6fbffffe6       | mov                 byte ptr [ebp - 0x43a], 0xe6
            //   c685c7fbffff36       | mov                 byte ptr [ebp - 0x439], 0x36

        $sequence_23 = { c685c4faffffea c685c5fafffff2 c685c6faffffb3 c685c7faffff12 }
            // n = 4, score = 300
            //   c685c4faffffea       | mov                 byte ptr [ebp - 0x53c], 0xea
            //   c685c5fafffff2       | mov                 byte ptr [ebp - 0x53b], 0xf2
            //   c685c6faffffb3       | mov                 byte ptr [ebp - 0x53a], 0xb3
            //   c685c7faffff12       | mov                 byte ptr [ebp - 0x539], 0x12

    condition:
        7 of them and filesize < 4325376
}