rule win_webc2_ausov_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.webc2_ausov."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_ausov"
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
        $sequence_0 = { 83c404 8b4d0c 894104 e9???????? 8dbdfcfbffff 83c9ff 33c0 }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   894104               | mov                 dword ptr [ecx + 4], eax
            //   e9????????           |                     
            //   8dbdfcfbffff         | lea                 edi, dword ptr [ebp - 0x404]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 85c9 7417 8b0d???????? 85c9 }
            // n = 4, score = 100
            //   85c9                 | test                ecx, ecx
            //   7417                 | je                  0x19
            //   8b0d????????         |                     
            //   85c9                 | test                ecx, ecx

        $sequence_2 = { 8b85f8fbffff 50 e8???????? 83c408 8985f4fbffff }
            // n = 5, score = 100
            //   8b85f8fbffff         | mov                 eax, dword ptr [ebp - 0x408]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8985f4fbffff         | mov                 dword ptr [ebp - 0x40c], eax

        $sequence_3 = { 50 6a00 683f000f00 6a00 6a00 6a00 8d8df8fdffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6a00                 | push                0
            //   683f000f00           | push                0xf003f
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d8df8fdffff         | lea                 ecx, dword ptr [ebp - 0x208]

        $sequence_4 = { e9???????? bf???????? 8d95a8faffff 83c9ff 33c0 f2ae }
            // n = 6, score = 100
            //   e9????????           |                     
            //   bf????????           |                     
            //   8d95a8faffff         | lea                 edx, dword ptr [ebp - 0x558]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

        $sequence_5 = { c685c8fdffff00 b90d000000 33c0 8dbdc9fdffff f3ab }
            // n = 5, score = 100
            //   c685c8fdffff00       | mov                 byte ptr [ebp - 0x238], 0
            //   b90d000000           | mov                 ecx, 0xd
            //   33c0                 | xor                 eax, eax
            //   8dbdc9fdffff         | lea                 edi, dword ptr [ebp - 0x237]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_6 = { 8b4d0c 894104 e9???????? 8dbdfcfbffff 83c9ff 33c0 f2ae }
            // n = 7, score = 100
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   894104               | mov                 dword ptr [ecx + 4], eax
            //   e9????????           |                     
            //   8dbdfcfbffff         | lea                 edi, dword ptr [ebp - 0x404]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

        $sequence_7 = { 52 8b450c 50 8b8df4fbffff 51 }
            // n = 5, score = 100
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8b8df4fbffff         | mov                 ecx, dword ptr [ebp - 0x40c]
            //   51                   | push                ecx

        $sequence_8 = { f3a5 8bcb 83e103 f3a4 0f8407000000 }
            // n = 5, score = 100
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bcb                 | mov                 ecx, ebx
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   0f8407000000         | je                  0xd

        $sequence_9 = { 8b8df4fbffff 51 ff15???????? 0f8407000000 }
            // n = 4, score = 100
            //   8b8df4fbffff         | mov                 ecx, dword ptr [ebp - 0x40c]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   0f8407000000         | je                  0xd

    condition:
        7 of them and filesize < 40960
}