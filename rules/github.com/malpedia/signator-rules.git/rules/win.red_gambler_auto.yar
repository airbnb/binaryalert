rule win_red_gambler_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.red_gambler."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.red_gambler"
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
        $sequence_0 = { 53 56 57 8bd8 53 ff15???????? 8d7002 }
            // n = 7, score = 500
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bd8                 | mov                 ebx, eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8d7002               | lea                 esi, dword ptr [eax + 2]

        $sequence_1 = { 8906 8b450c 53 894e08 50 }
            // n = 5, score = 400
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   53                   | push                ebx
            //   894e08               | mov                 dword ptr [esi + 8], ecx
            //   50                   | push                eax

        $sequence_2 = { 8b3d???????? 8d9b00000000 8d4c2434 51 53 ff15???????? 85c0 }
            // n = 7, score = 400
            //   8b3d????????         |                     
            //   8d9b00000000         | lea                 ebx, dword ptr [ebx]
            //   8d4c2434             | lea                 ecx, dword ptr [esp + 0x34]
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_3 = { 57 53 ffd6 85c0 7538 }
            // n = 5, score = 400
            //   57                   | push                edi
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7538                 | jne                 0x3a

        $sequence_4 = { 74ec 8a8860f00300 8db05cf00300 8b06 8945ec }
            // n = 5, score = 400
            //   74ec                 | je                  0xffffffee
            //   8a8860f00300         | mov                 cl, byte ptr [eax + 0x3f060]
            //   8db05cf00300         | lea                 esi, dword ptr [eax + 0x3f05c]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_5 = { 837d0c10 56 57 7305 8b7d08 eb05 8b4508 }
            // n = 7, score = 400
            //   837d0c10             | cmp                 dword ptr [ebp + 0xc], 0x10
            //   56                   | push                esi
            //   57                   | push                edi
            //   7305                 | jae                 7
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   eb05                 | jmp                 7
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_6 = { 72bf 5e 33c0 5b }
            // n = 4, score = 400
            //   72bf                 | jb                  0xffffffc1
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx

        $sequence_7 = { 83ec18 8b0d???????? 8b15???????? 53 8bd8 }
            // n = 5, score = 400
            //   83ec18               | sub                 esp, 0x18
            //   8b0d????????         |                     
            //   8b15????????         |                     
            //   53                   | push                ebx
            //   8bd8                 | mov                 ebx, eax

        $sequence_8 = { 2b2a bee7eee947 7c26 0e }
            // n = 4, score = 300
            //   2b2a                 | sub                 ebp, dword ptr [edx]
            //   bee7eee947           | mov                 esi, 0x47e9eee7
            //   7c26                 | jl                  0x28
            //   0e                   | push                cs

        $sequence_9 = { e779 bcb8b4b0ac e779 9e e7a8 a4 }
            // n = 6, score = 300
            //   e779                 | out                 0x79, eax
            //   bcb8b4b0ac           | mov                 esp, 0xacb0b4b8
            //   e779                 | out                 0x79, eax
            //   9e                   | sahf                
            //   e7a8                 | out                 0xa8, eax
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]

        $sequence_10 = { 665b e17a 6c 8737 }
            // n = 4, score = 300
            //   665b                 | pop                 bx
            //   e17a                 | loope               0x7c
            //   6c                   | insb                byte ptr es:[edi], dx
            //   8737                 | xchg                dword ptr [edi], esi

        $sequence_11 = { 14cf fd 67144e 1916 }
            // n = 4, score = 300
            //   14cf                 | adc                 al, 0xcf
            //   fd                   | std                 
            //   67144e               | adc                 al, 0x4e
            //   1916                 | sbb                 dword ptr [esi], edx

        $sequence_12 = { a0???????? 799e 94 90 8c888480799e }
            // n = 5, score = 300
            //   a0????????           |                     
            //   799e                 | jns                 0xffffffa0
            //   94                   | xchg                eax, esp
            //   90                   | nop                 
            //   8c888480799e         | mov                 word ptr [eax - 0x61867f7c], cs

        $sequence_13 = { 8d8d98fdffff 51 8d9598feffff 52 }
            // n = 4, score = 300
            //   8d8d98fdffff         | lea                 ecx, dword ptr [ebp - 0x268]
            //   51                   | push                ecx
            //   8d9598feffff         | lea                 edx, dword ptr [ebp - 0x168]
            //   52                   | push                edx

        $sequence_14 = { 8d9598feffff 52 ff15???????? 8d8594fbffff }
            // n = 4, score = 300
            //   8d9598feffff         | lea                 edx, dword ptr [ebp - 0x168]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8d8594fbffff         | lea                 eax, dword ptr [ebp - 0x46c]

        $sequence_15 = { 3d067c263c 3c3d 9e e7bd e600 3e3e25162f062d 2b2a }
            // n = 7, score = 300
            //   3d067c263c           | cmp                 eax, 0x3c267c06
            //   3c3d                 | cmp                 al, 0x3d
            //   9e                   | sahf                
            //   e7bd                 | out                 0xbd, eax
            //   e600                 | out                 0, al
            //   3e3e25162f062d       | and                 eax, 0x2d062f16
            //   2b2a                 | sub                 ebp, dword ptr [edx]

        $sequence_16 = { ff15???????? 8d5598 52 8d8598fdffff }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   8d5598               | lea                 edx, dword ptr [ebp - 0x68]
            //   52                   | push                edx
            //   8d8598fdffff         | lea                 eax, dword ptr [ebp - 0x268]

        $sequence_17 = { 52 8d8598fdffff 50 68???????? }
            // n = 4, score = 300
            //   52                   | push                edx
            //   8d8598fdffff         | lea                 eax, dword ptr [ebp - 0x268]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_18 = { 4c 40 34f3 3ccf f3281c14 }
            // n = 5, score = 300
            //   4c                   | dec                 esp
            //   40                   | inc                 eax
            //   34f3                 | xor                 al, 0xf3
            //   3ccf                 | cmp                 al, 0xcf
            //   f3281c14             | sub                 byte ptr [esp + edx], bl

        $sequence_19 = { 50 68???????? 8d8d98fbffff 68???????? }
            // n = 4, score = 300
            //   50                   | push                eax
            //   68????????           |                     
            //   8d8d98fbffff         | lea                 ecx, dword ptr [ebp - 0x468]
            //   68????????           |                     

        $sequence_20 = { 8d8d98fbffff 68???????? 51 ff15???????? 83c414 }
            // n = 5, score = 300
            //   8d8d98fbffff         | lea                 ecx, dword ptr [ebp - 0x468]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14

        $sequence_21 = { 002f 2f 93 ee b4ed }
            // n = 5, score = 300
            //   002f                 | add                 byte ptr [edi], ch
            //   2f                   | das                 
            //   93                   | xchg                eax, ebx
            //   ee                   | out                 dx, al
            //   b4ed                 | mov                 ah, 0xed

        $sequence_22 = { 6800010000 8d85fcfeffff 50 6a00 ff15???????? }
            // n = 5, score = 300
            //   6800010000           | push                0x100
            //   8d85fcfeffff         | lea                 eax, dword ptr [ebp - 0x104]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_23 = { 8d9598fbffff 52 68???????? 6a00 }
            // n = 4, score = 300
            //   8d9598fbffff         | lea                 edx, dword ptr [ebp - 0x468]
            //   52                   | push                edx
            //   68????????           |                     
            //   6a00                 | push                0

        $sequence_24 = { ff15???????? 83c414 6a00 6a00 8d9598fbffff 52 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d9598fbffff         | lea                 edx, dword ptr [ebp - 0x468]
            //   52                   | push                edx

        $sequence_25 = { 40 68???????? 50 ff15???????? 8d85fcfeffff 50 ff15???????? }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d85fcfeffff         | lea                 eax, dword ptr [ebp - 0x104]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_26 = { 8bf0 85f6 0f856effffff 6a00 ff15???????? cc }
            // n = 6, score = 100
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   0f856effffff         | jne                 0xffffff74
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   cc                   | int3                

        $sequence_27 = { 833cf5d481400001 751d 8d04f5d0814000 8938 68a00f0000 ff30 83c718 }
            // n = 7, score = 100
            //   833cf5d481400001     | cmp                 dword ptr [esi*8 + 0x4081d4], 1
            //   751d                 | jne                 0x1f
            //   8d04f5d0814000       | lea                 eax, dword ptr [esi*8 + 0x4081d0]
            //   8938                 | mov                 dword ptr [eax], edi
            //   68a00f0000           | push                0xfa0
            //   ff30                 | push                dword ptr [eax]
            //   83c718               | add                 edi, 0x18

        $sequence_28 = { 83c414 c3 6a08 68???????? }
            // n = 4, score = 100
            //   83c414               | add                 esp, 0x14
            //   c3                   | ret                 
            //   6a08                 | push                8
            //   68????????           |                     

        $sequence_29 = { 7524 a1???????? a3???????? a1???????? c705????????6b214000 8935???????? }
            // n = 6, score = 100
            //   7524                 | jne                 0x26
            //   a1????????           |                     
            //   a3????????           |                     
            //   a1????????           |                     
            //   c705????????6b214000     |     
            //   8935????????         |                     

        $sequence_30 = { 6a00 ff15???????? 6a5c 8d85fcfeffff 50 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a5c                 | push                0x5c
            //   8d85fcfeffff         | lea                 eax, dword ptr [ebp - 0x104]
            //   50                   | push                eax

        $sequence_31 = { 3b0cc5d8694000 740a 40 83f816 72ee }
            // n = 5, score = 100
            //   3b0cc5d8694000       | cmp                 ecx, dword ptr [eax*8 + 0x4069d8]
            //   740a                 | je                  0xc
            //   40                   | inc                 eax
            //   83f816               | cmp                 eax, 0x16
            //   72ee                 | jb                  0xfffffff0

    condition:
        7 of them and filesize < 327680
}