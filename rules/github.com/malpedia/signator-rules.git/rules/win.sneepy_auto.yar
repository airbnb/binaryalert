rule win_sneepy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.sneepy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sneepy"
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
        $sequence_0 = { c1e902 f3a5 8bc8 8d95f0feffff 83e103 68???????? 52 }
            // n = 7, score = 100
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   8d95f0feffff         | lea                 edx, dword ptr [ebp - 0x110]
            //   83e103               | and                 ecx, 3
            //   68????????           |                     
            //   52                   | push                edx

        $sequence_1 = { 85f6 7fa2 8b85ecfcffff 50 }
            // n = 4, score = 100
            //   85f6                 | test                esi, esi
            //   7fa2                 | jg                  0xffffffa4
            //   8b85ecfcffff         | mov                 eax, dword ptr [ebp - 0x314]
            //   50                   | push                eax

        $sequence_2 = { 68???????? 57 ffd3 8b85ecfcffff }
            // n = 4, score = 100
            //   68????????           |                     
            //   57                   | push                edi
            //   ffd3                 | call                ebx
            //   8b85ecfcffff         | mov                 eax, dword ptr [ebp - 0x314]

        $sequence_3 = { 8d8df0feffff 6a00 51 8985e8fcffff e8???????? 83c40c 33c0 }
            // n = 7, score = 100
            //   8d8df0feffff         | lea                 ecx, dword ptr [ebp - 0x110]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   8985e8fcffff         | mov                 dword ptr [ebp - 0x318], eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 68???????? 52 f3a4 e8???????? 8bf0 83c408 }
            // n = 6, score = 100
            //   68????????           |                     
            //   52                   | push                edx
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c408               | add                 esp, 8

        $sequence_5 = { c745e800000000 e8???????? 8b4de8 8d55ec }
            // n = 4, score = 100
            //   c745e800000000       | mov                 dword ptr [ebp - 0x18], 0
            //   e8????????           |                     
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8d55ec               | lea                 edx, dword ptr [ebp - 0x14]

        $sequence_6 = { 66895004 8d45ac 50 e8???????? 8d45ac 83c404 8bd0 }
            // n = 7, score = 100
            //   66895004             | mov                 word ptr [eax + 4], dx
            //   8d45ac               | lea                 eax, dword ptr [ebp - 0x54]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d45ac               | lea                 eax, dword ptr [ebp - 0x54]
            //   83c404               | add                 esp, 4
            //   8bd0                 | mov                 edx, eax

        $sequence_7 = { 66a1???????? 53 668907 ff15???????? 8bc8 }
            // n = 5, score = 100
            //   66a1????????         |                     
            //   53                   | push                ebx
            //   668907               | mov                 word ptr [edi], ax
            //   ff15????????         |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_8 = { 83c8ff eb1b 8bc6 c1f805 8b048560314100 83e61f c1e606 }
            // n = 7, score = 100
            //   83c8ff               | or                  eax, 0xffffffff
            //   eb1b                 | jmp                 0x1d
            //   8bc6                 | mov                 eax, esi
            //   c1f805               | sar                 eax, 5
            //   8b048560314100       | mov                 eax, dword ptr [eax*4 + 0x413160]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6

        $sequence_9 = { 7518 56 e8???????? 8b55fc 52 e8???????? }
            // n = 6, score = 100
            //   7518                 | jne                 0x1a
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx
            //   e8????????           |                     

    condition:
        7 of them and filesize < 188416
}