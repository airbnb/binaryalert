rule win_ismagent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.ismagent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ismagent"
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
        $sequence_0 = { 8a01 8d4901 88440aff 84c0 75f3 837c241400 7422 }
            // n = 7, score = 200
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   8d4901               | lea                 ecx, dword ptr [ecx + 1]
            //   88440aff             | mov                 byte ptr [edx + ecx - 1], al
            //   84c0                 | test                al, al
            //   75f3                 | jne                 0xfffffff5
            //   837c241400           | cmp                 dword ptr [esp + 0x14], 0
            //   7422                 | je                  0x24

        $sequence_1 = { 68000000a0 ff7510 51 57 ffd0 68???????? }
            // n = 6, score = 200
            //   68000000a0           | push                0xa0000000
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   51                   | push                ecx
            //   57                   | push                edi
            //   ffd0                 | call                eax
            //   68????????           |                     

        $sequence_2 = { 83e23f 83e13f 0fb689700c4200 884e02 0fb68a700c4200 884e03 83c604 }
            // n = 7, score = 200
            //   83e23f               | and                 edx, 0x3f
            //   83e13f               | and                 ecx, 0x3f
            //   0fb689700c4200       | movzx               ecx, byte ptr [ecx + 0x420c70]
            //   884e02               | mov                 byte ptr [esi + 2], cl
            //   0fb68a700c4200       | movzx               ecx, byte ptr [edx + 0x420c70]
            //   884e03               | mov                 byte ptr [esi + 3], cl
            //   83c604               | add                 esi, 4

        $sequence_3 = { 660f58e0 660fc5c400 25f0070000 660f28a040024200 660f28b830fe4100 660f54f0 660f5cc6 }
            // n = 7, score = 200
            //   660f58e0             | addpd               xmm4, xmm0
            //   660fc5c400           | pextrw              eax, xmm4, 0
            //   25f0070000           | and                 eax, 0x7f0
            //   660f28a040024200     | movapd              xmm4, xmmword ptr [eax + 0x420240]
            //   660f28b830fe4100     | movapd              xmm7, xmmword ptr [eax + 0x41fe30]
            //   660f54f0             | andpd               xmm6, xmm0
            //   660f5cc6             | subpd               xmm0, xmm6

        $sequence_4 = { 8945fc 8b4508 53 8985b4f3ffff 8bd9 8b450c 33c9 }
            // n = 7, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   53                   | push                ebx
            //   8985b4f3ffff         | mov                 dword ptr [ebp - 0xc4c], eax
            //   8bd9                 | mov                 ebx, ecx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   33c9                 | xor                 ecx, ecx

        $sequence_5 = { 8974241c 68???????? ff74242c e8???????? }
            // n = 4, score = 200
            //   8974241c             | mov                 dword ptr [esp + 0x1c], esi
            //   68????????           |                     
            //   ff74242c             | push                dword ptr [esp + 0x2c]
            //   e8????????           |                     

        $sequence_6 = { 56 57 68???????? 8bda 8bf9 }
            // n = 5, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   68????????           |                     
            //   8bda                 | mov                 ebx, edx
            //   8bf9                 | mov                 edi, ecx

        $sequence_7 = { 03c6 6a64 50 8d8424f00a0000 50 }
            // n = 5, score = 200
            //   03c6                 | add                 eax, esi
            //   6a64                 | push                0x64
            //   50                   | push                eax
            //   8d8424f00a0000       | lea                 eax, dword ptr [esp + 0xaf0]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 327680
}