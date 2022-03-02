rule win_poison_ivy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.poison_ivy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poison_ivy"
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
        $sequence_0 = { 6a01 6a00 8d86120e0000 50 ff75fc ff563d ff75fc }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   8d86120e0000         | lea                 eax, dword ptr [esi + 0xe12]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff563d               | call                dword ptr [esi + 0x3d]
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_1 = { 51 ff5635 68ff000000 8d86b1060000 50 6a01 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   ff5635               | call                dword ptr [esi + 0x35]
            //   68ff000000           | push                0xff
            //   8d86b1060000         | lea                 eax, dword ptr [esi + 0x6b1]
            //   50                   | push                eax
            //   6a01                 | push                1

        $sequence_2 = { ff9681000000 80beaf08000001 7507 b902000080 eb05 }
            // n = 5, score = 100
            //   ff9681000000         | call                dword ptr [esi + 0x81]
            //   80beaf08000001       | cmp                 byte ptr [esi + 0x8af], 1
            //   7507                 | jne                 9
            //   b902000080           | mov                 ecx, 0x80000002
            //   eb05                 | jmp                 7

        $sequence_3 = { 683f000f00 6a00 57 51 ff5635 }
            // n = 5, score = 100
            //   683f000f00           | push                0xf003f
            //   6a00                 | push                0
            //   57                   | push                edi
            //   51                   | push                ecx
            //   ff5635               | call                dword ptr [esi + 0x35]

        $sequence_4 = { 59 51 57 ff9681000000 8d45fc 50 }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   51                   | push                ecx
            //   57                   | push                edi
            //   ff9681000000         | call                dword ptr [esi + 0x81]
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax

        $sequence_5 = { b902000080 eb05 b901000080 8d45fc 50 683f000f00 6a00 }
            // n = 7, score = 100
            //   b902000080           | mov                 ecx, 0x80000002
            //   eb05                 | jmp                 7
            //   b901000080           | mov                 ecx, 0x80000001
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   683f000f00           | push                0xf003f
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 204800
}