rule win_scarabey_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.scarabey."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scarabey"
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
        $sequence_0 = { 898df8d3ffff a3???????? ff15???????? 833d????????00 7414 833d????????00 740b }
            // n = 7, score = 100
            //   898df8d3ffff         | mov                 dword ptr [ebp - 0x2c08], ecx
            //   a3????????           |                     
            //   ff15????????         |                     
            //   833d????????00       |                     
            //   7414                 | je                  0x16
            //   833d????????00       |                     
            //   740b                 | je                  0xd

        $sequence_1 = { 8d8ea40d0000 6a0a e8???????? 899ec00d0000 899ec40d0000 899ecc0d0000 c786c80d0000d49e5300 }
            // n = 7, score = 100
            //   8d8ea40d0000         | lea                 ecx, dword ptr [esi + 0xda4]
            //   6a0a                 | push                0xa
            //   e8????????           |                     
            //   899ec00d0000         | mov                 dword ptr [esi + 0xdc0], ebx
            //   899ec40d0000         | mov                 dword ptr [esi + 0xdc4], ebx
            //   899ecc0d0000         | mov                 dword ptr [esi + 0xdcc], ebx
            //   c786c80d0000d49e5300     | mov    dword ptr [esi + 0xdc8], 0x539ed4

        $sequence_2 = { 0f84e3feffff 8b4f04 8b01 ff5078 a900000008 74e3 3bfb }
            // n = 7, score = 100
            //   0f84e3feffff         | je                  0xfffffee9
            //   8b4f04               | mov                 ecx, dword ptr [edi + 4]
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   ff5078               | call                dword ptr [eax + 0x78]
            //   a900000008           | test                eax, 0x8000000
            //   74e3                 | je                  0xffffffe5
            //   3bfb                 | cmp                 edi, ebx

        $sequence_3 = { 6a36 8945d4 ffd6 8bf0 895ddc c745d880185300 56 }
            // n = 7, score = 100
            //   6a36                 | push                0x36
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   ffd6                 | call                esi
            //   8bf0                 | mov                 esi, eax
            //   895ddc               | mov                 dword ptr [ebp - 0x24], ebx
            //   c745d880185300       | mov                 dword ptr [ebp - 0x28], 0x531880
            //   56                   | push                esi

        $sequence_4 = { 8b440824 3bc3 0f8431010000 8b4004 }
            // n = 4, score = 100
            //   8b440824             | mov                 eax, dword ptr [eax + ecx + 0x24]
            //   3bc3                 | cmp                 eax, ebx
            //   0f8431010000         | je                  0x137
            //   8b4004               | mov                 eax, dword ptr [eax + 4]

        $sequence_5 = { 884dfa ff15???????? 33c0 8d8d10f1ffff 51 89bd10f1ffff 898514f1ffff }
            // n = 7, score = 100
            //   884dfa               | mov                 byte ptr [ebp - 6], cl
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   8d8d10f1ffff         | lea                 ecx, dword ptr [ebp - 0xef0]
            //   51                   | push                ecx
            //   89bd10f1ffff         | mov                 dword ptr [ebp - 0xef0], edi
            //   898514f1ffff         | mov                 dword ptr [ebp - 0xeec], eax

        $sequence_6 = { 037914 53 53 ff75e8 e8???????? }
            // n = 5, score = 100
            //   037914               | add                 edi, dword ptr [ecx + 0x14]
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   e8????????           |                     

        $sequence_7 = { fec3 750a 8b7df0 3b7e10 7cb3 eb75 8b4614 }
            // n = 7, score = 100
            //   fec3                 | inc                 bl
            //   750a                 | jne                 0xc
            //   8b7df0               | mov                 edi, dword ptr [ebp - 0x10]
            //   3b7e10               | cmp                 edi, dword ptr [esi + 0x10]
            //   7cb3                 | jl                  0xffffffb5
            //   eb75                 | jmp                 0x77
            //   8b4614               | mov                 eax, dword ptr [esi + 0x14]

        $sequence_8 = { ff7008 8bce ff5208 3bdf 75e8 8b4588 }
            // n = 6, score = 100
            //   ff7008               | push                dword ptr [eax + 8]
            //   8bce                 | mov                 ecx, esi
            //   ff5208               | call                dword ptr [edx + 8]
            //   3bdf                 | cmp                 ebx, edi
            //   75e8                 | jne                 0xffffffea
            //   8b4588               | mov                 eax, dword ptr [ebp - 0x78]

        $sequence_9 = { f7bd04d7ffff 83f801 7dea be01000000 eb09 c1ee10 }
            // n = 6, score = 100
            //   f7bd04d7ffff         | idiv                dword ptr [ebp - 0x28fc]
            //   83f801               | cmp                 eax, 1
            //   7dea                 | jge                 0xffffffec
            //   be01000000           | mov                 esi, 1
            //   eb09                 | jmp                 0xb
            //   c1ee10               | shr                 esi, 0x10

    condition:
        7 of them and filesize < 3580928
}