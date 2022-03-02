rule win_mosquito_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.mosquito."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mosquito"
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
        $sequence_0 = { f7d8 1bc0 83e0b4 83c04c }
            // n = 4, score = 400
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   83e0b4               | and                 eax, 0xffffffb4
            //   83c04c               | add                 eax, 0x4c

        $sequence_1 = { 52 50 6a00 6801c1fd7d }
            // n = 4, score = 400
            //   52                   | push                edx
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6801c1fd7d           | push                0x7dfdc101

        $sequence_2 = { f3a5 ff942464020000 81c450020000 85c0 }
            // n = 4, score = 400
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff942464020000       | call                dword ptr [esp + 0x264]
            //   81c450020000         | add                 esp, 0x250
            //   85c0                 | test                eax, eax

        $sequence_3 = { 8b7e10 893c13 83c304 837e1408 7204 }
            // n = 5, score = 300
            //   8b7e10               | mov                 edi, dword ptr [esi + 0x10]
            //   893c13               | mov                 dword ptr [ebx + edx], edi
            //   83c304               | add                 ebx, 4
            //   837e1408             | cmp                 dword ptr [esi + 0x14], 8
            //   7204                 | jb                  6

        $sequence_4 = { 8b4b04 8bd0 8d7102 668b01 }
            // n = 4, score = 300
            //   8b4b04               | mov                 ecx, dword ptr [ebx + 4]
            //   8bd0                 | mov                 edx, eax
            //   8d7102               | lea                 esi, dword ptr [ecx + 2]
            //   668b01               | mov                 ax, word ptr [ecx]

        $sequence_5 = { 8bc7 8b4c2428 64890d00000000 59 5f 5e 8be5 }
            // n = 7, score = 300
            //   8bc7                 | mov                 eax, edi
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp

        $sequence_6 = { 8bfc f3a5 ff942460020000 81c450020000 }
            // n = 4, score = 300
            //   8bfc                 | mov                 edi, esp
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff942460020000       | call                dword ptr [esp + 0x260]
            //   81c450020000         | add                 esp, 0x250

        $sequence_7 = { 7305 8b4908 eb04 8bd1 8b09 80792100 }
            // n = 6, score = 300
            //   7305                 | jae                 7
            //   8b4908               | mov                 ecx, dword ptr [ecx + 8]
            //   eb04                 | jmp                 6
            //   8bd1                 | mov                 edx, ecx
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   80792100             | cmp                 byte ptr [ecx + 0x21], 0

        $sequence_8 = { e8???????? 8b45fc 3b4619 75e5 5e 8be5 5d }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   3b4619               | cmp                 eax, dword ptr [esi + 0x19]
            //   75e5                 | jne                 0xffffffe7
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_9 = { e8???????? 6a20 8bf0 e8???????? 8bc8 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   6a20                 | push                0x20
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_10 = { 8b4d20 2bf9 6a3a 8bc7 5e 99 f7fe }
            // n = 7, score = 300
            //   8b4d20               | mov                 ecx, dword ptr [ebp + 0x20]
            //   2bf9                 | sub                 edi, ecx
            //   6a3a                 | push                0x3a
            //   8bc7                 | mov                 eax, edi
            //   5e                   | pop                 esi
            //   99                   | cdq                 
            //   f7fe                 | idiv                esi

        $sequence_11 = { e8???????? 6a20 e8???????? 83c40c }
            // n = 4, score = 300
            //   e8????????           |                     
            //   6a20                 | push                0x20
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_12 = { e8???????? 8b45fc 3bc3 75e8 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   3bc3                 | cmp                 eax, ebx
            //   75e8                 | jne                 0xffffffea

        $sequence_13 = { 7074 299319ff1556 57 0800 }
            // n = 4, score = 200
            //   7074                 | jo                  0x76
            //   299319ff1556         | sub                 dword ptr [ebx + 0x5615ff19], edx
            //   57                   | push                edi
            //   0800                 | or                  byte ptr [eax], al

        $sequence_14 = { 7051 0489 5d 00e8 3101 8bc7 }
            // n = 6, score = 200
            //   7051                 | jo                  0x53
            //   0489                 | add                 al, 0x89
            //   5d                   | pop                 ebp
            //   00e8                 | add                 al, ch
            //   3101                 | xor                 dword ptr [ecx], eax
            //   8bc7                 | mov                 eax, edi

        $sequence_15 = { 708b c600cc 8bf0 80780070 }
            // n = 4, score = 200
            //   708b                 | jo                  0xffffff8d
            //   c600cc               | mov                 byte ptr [eax], 0xcc
            //   8bf0                 | mov                 esi, eax
            //   80780070             | cmp                 byte ptr [eax], 0x70

        $sequence_16 = { 708d 46 1001 45 }
            // n = 4, score = 200
            //   708d                 | jo                  0xffffff8f
            //   46                   | inc                 esi
            //   1001                 | adc                 byte ptr [ecx], al
            //   45                   | inc                 ebp

        $sequence_17 = { 7068 3100 83680010 64006c64a1 }
            // n = 4, score = 200
            //   7068                 | jo                  0x6a
            //   3100                 | xor                 dword ptr [eax], eax
            //   83680010             | sub                 dword ptr [eax], 0x10
            //   64006c64a1           | add                 byte ptr fs:[esp - 0x5f], ch

        $sequence_18 = { 7083 ec 54 2465 }
            // n = 4, score = 200
            //   7083                 | jo                  0xffffff85
            //   ec                   | in                  al, dx
            //   54                   | push                esp
            //   2465                 | and                 al, 0x65

    condition:
        7 of them and filesize < 1015808
}