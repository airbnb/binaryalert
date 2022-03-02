rule win_montysthree_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.montysthree."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.montysthree"
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
        $sequence_0 = { ff75e0 50 6aff 53 }
            // n = 4, score = 200
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   50                   | push                eax
            //   6aff                 | push                -1
            //   53                   | push                ebx

        $sequence_1 = { 395dfc 7409 ff75fc ff15???????? 6a01 }
            // n = 5, score = 200
            //   395dfc               | cmp                 dword ptr [ebp - 4], ebx
            //   7409                 | je                  0xb
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   6a01                 | push                1

        $sequence_2 = { e8???????? 83c40c 8d4d44 e8???????? ffd7 50 8d4544 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d4d44               | lea                 ecx, dword ptr [ebp + 0x44]
            //   e8????????           |                     
            //   ffd7                 | call                edi
            //   50                   | push                eax
            //   8d4544               | lea                 eax, dword ptr [ebp + 0x44]

        $sequence_3 = { 6a04 8d45e8 50 8d4d18 e8???????? 8bc8 e8???????? }
            // n = 7, score = 200
            //   6a04                 | push                4
            //   8d45e8               | lea                 eax, dword ptr [ebp - 0x18]
            //   50                   | push                eax
            //   8d4d18               | lea                 ecx, dword ptr [ebp + 0x18]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     

        $sequence_4 = { 8d4d50 e8???????? 50 e8???????? 53 e8???????? }
            // n = 6, score = 200
            //   8d4d50               | lea                 ecx, dword ptr [ebp + 0x50]
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_5 = { 85c0 0f858efdffff 8b35???????? ffd6 83f812 }
            // n = 5, score = 200
            //   85c0                 | test                eax, eax
            //   0f858efdffff         | jne                 0xfffffd94
            //   8b35????????         |                     
            //   ffd6                 | call                esi
            //   83f812               | cmp                 eax, 0x12

        $sequence_6 = { e8???????? 83c424 397568 0f85b2020000 39756c }
            // n = 5, score = 200
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   397568               | cmp                 dword ptr [ebp + 0x68], esi
            //   0f85b2020000         | jne                 0x2b8
            //   39756c               | cmp                 dword ptr [ebp + 0x6c], esi

        $sequence_7 = { 6a10 68???????? e8???????? 33ff 897dfc 393d???????? }
            // n = 6, score = 200
            //   6a10                 | push                0x10
            //   68????????           |                     
            //   e8????????           |                     
            //   33ff                 | xor                 edi, edi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   393d????????         |                     

        $sequence_8 = { 8b3d???????? 50 ffd7 85c0 763f 8d8574e7ffff }
            // n = 6, score = 200
            //   8b3d????????         |                     
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   763f                 | jbe                 0x41
            //   8d8574e7ffff         | lea                 eax, dword ptr [ebp - 0x188c]

        $sequence_9 = { ff36 ff33 ff75f8 ff15???????? 85c0 7541 ff15???????? }
            // n = 7, score = 200
            //   ff36                 | push                dword ptr [esi]
            //   ff33                 | push                dword ptr [ebx]
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7541                 | jne                 0x43
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 458752
}