rule win_ayegent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.ayegent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ayegent"
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
        $sequence_0 = { 50 c684241c02000001 ffd6 6a00 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   c684241c02000001     | mov                 byte ptr [esp + 0x21c], 1
            //   ffd6                 | call                esi
            //   6a00                 | push                0

        $sequence_1 = { 8b4c240c 8b542408 8d442408 50 51 52 ff15???????? }
            // n = 7, score = 100
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   8d442408             | lea                 eax, dword ptr [esp + 8]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_2 = { 56 ff15???????? 56 8b35???????? ffd6 8d4c241c 51 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi
            //   8b35????????         |                     
            //   ffd6                 | call                esi
            //   8d4c241c             | lea                 ecx, dword ptr [esp + 0x1c]
            //   51                   | push                ecx

        $sequence_3 = { a1???????? 68???????? 50 ff15???????? 8b4c2428 8b542424 51 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   8b542424             | mov                 edx, dword ptr [esp + 0x24]
            //   51                   | push                ecx

        $sequence_4 = { 52 50 ffd6 6a00 8d8c2414010000 }
            // n = 5, score = 100
            //   52                   | push                edx
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   6a00                 | push                0
            //   8d8c2414010000       | lea                 ecx, dword ptr [esp + 0x114]

        $sequence_5 = { 0890619e4000 40 3bc7 76f5 41 41 803900 }
            // n = 7, score = 100
            //   0890619e4000         | or                  byte ptr [eax + 0x409e61], dl
            //   40                   | inc                 eax
            //   3bc7                 | cmp                 eax, edi
            //   76f5                 | jbe                 0xfffffff7
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   803900               | cmp                 byte ptr [ecx], 0

        $sequence_6 = { 50 53 68???????? 68???????? 885c2428 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   53                   | push                ebx
            //   68????????           |                     
            //   68????????           |                     
            //   885c2428             | mov                 byte ptr [esp + 0x28], bl

        $sequence_7 = { 52 a3???????? ffd6 a3???????? b940000000 33c0 }
            // n = 6, score = 100
            //   52                   | push                edx
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax

        $sequence_8 = { a1???????? 68???????? 50 ff15???????? 8b4c2408 8b542404 }
            // n = 6, score = 100
            //   a1????????           |                     
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   8b542404             | mov                 edx, dword ptr [esp + 4]

        $sequence_9 = { 6a00 e8???????? 68ac0d0000 e8???????? 6a00 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   e8????????           |                     
            //   68ac0d0000           | push                0xdac
            //   e8????????           |                     
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 90112
}