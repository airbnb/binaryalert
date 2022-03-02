rule win_joao_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.joao."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.joao"
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
        $sequence_0 = { 8b55e4 2bc7 8bf8 3bd7 7202 8bd7 }
            // n = 6, score = 400
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   2bc7                 | sub                 eax, edi
            //   8bf8                 | mov                 edi, eax
            //   3bd7                 | cmp                 edx, edi
            //   7202                 | jb                  4
            //   8bd7                 | mov                 edx, edi

        $sequence_1 = { 6aff 52 8d4dd0 e8???????? 83f8ff }
            // n = 5, score = 400
            //   6aff                 | push                -1
            //   52                   | push                edx
            //   8d4dd0               | lea                 ecx, dword ptr [ebp - 0x30]
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1

        $sequence_2 = { 68ffff1f00 ff15???????? 8bf0 56 ff15???????? 56 ff15???????? }
            // n = 7, score = 400
            //   68ffff1f00           | push                0x1fffff
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_3 = { 6a00 6a20 68???????? 57 56 ff15???????? 85c0 }
            // n = 7, score = 400
            //   6a00                 | push                0
            //   6a20                 | push                0x20
            //   68????????           |                     
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_4 = { 7522 8bcf e8???????? 3bf0 742a 8b4d10 0fbe56ff }
            // n = 7, score = 400
            //   7522                 | jne                 0x24
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   3bf0                 | cmp                 esi, eax
            //   742a                 | je                  0x2c
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   0fbe56ff             | movsx               edx, byte ptr [esi - 1]

        $sequence_5 = { 8be5 5d c20c00 6a40 6800300000 6a20 6a00 }
            // n = 7, score = 400
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   6a40                 | push                0x40
            //   6800300000           | push                0x3000
            //   6a20                 | push                0x20
            //   6a00                 | push                0

        $sequence_6 = { b804000000 5b 8be5 5d c20c00 6a40 }
            // n = 6, score = 400
            //   b804000000           | mov                 eax, 4
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   6a40                 | push                0x40

        $sequence_7 = { 6a01 8bcf e8???????? 8b06 8b4804 8b4c3138 }
            // n = 6, score = 400
            //   6a01                 | push                1
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   8b4c3138             | mov                 ecx, dword ptr [ecx + esi + 0x38]

        $sequence_8 = { 52 6a40 6a20 68???????? ff15???????? }
            // n = 5, score = 400
            //   52                   | push                edx
            //   6a40                 | push                0x40
            //   6a20                 | push                0x20
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_9 = { 56 894510 ffd0 8bf8 897dfc 85ff }
            // n = 6, score = 400
            //   56                   | push                esi
            //   894510               | mov                 dword ptr [ebp + 0x10], eax
            //   ffd0                 | call                eax
            //   8bf8                 | mov                 edi, eax
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   85ff                 | test                edi, edi

    condition:
        7 of them and filesize < 2867200
}