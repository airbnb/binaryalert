rule win_bunitu_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.bunitu."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bunitu"
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
        $sequence_0 = { 7614 6a02 ff75f0 ff15???????? ff75f0 }
            // n = 5, score = 1300
            //   7614                 | jbe                 0x16
            //   6a02                 | push                2
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff15????????         |                     
            //   ff75f0               | push                dword ptr [ebp - 0x10]

        $sequence_1 = { 8bd7 33c0 b970170000 f2ae 2bfa }
            // n = 5, score = 1300
            //   8bd7                 | mov                 edx, edi
            //   33c0                 | xor                 eax, eax
            //   b970170000           | mov                 ecx, 0x1770
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   2bfa                 | sub                 edi, edx

        $sequence_2 = { ffb524fdffff e8???????? eb12 6a08 68???????? }
            // n = 5, score = 1300
            //   ffb524fdffff         | push                dword ptr [ebp - 0x2dc]
            //   e8????????           |                     
            //   eb12                 | jmp                 0x14
            //   6a08                 | push                8
            //   68????????           |                     

        $sequence_3 = { 6800100000 8b4508 50 ff75ec e8???????? 0bc0 7e18 }
            // n = 7, score = 1300
            //   6800100000           | push                0x1000
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   e8????????           |                     
            //   0bc0                 | or                  eax, eax
            //   7e18                 | jle                 0x1a

        $sequence_4 = { ff15???????? ff75ec ff15???????? 837df000 7614 6a02 ff75f0 }
            // n = 7, score = 1300
            //   ff15????????         |                     
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff15????????         |                     
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0
            //   7614                 | jbe                 0x16
            //   6a02                 | push                2
            //   ff75f0               | push                dword ptr [ebp - 0x10]

        $sequence_5 = { c6472402 c70721000000 6a25 57 }
            // n = 4, score = 1300
            //   c6472402             | mov                 byte ptr [edi + 0x24], 2
            //   c70721000000         | mov                 dword ptr [edi], 0x21
            //   6a25                 | push                0x25
            //   57                   | push                edi

        $sequence_6 = { 51 57 ff75e0 e8???????? }
            // n = 4, score = 1300
            //   51                   | push                ecx
            //   57                   | push                edi
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   e8????????           |                     

        $sequence_7 = { ffb530feffff ff15???????? ffb530feffff ff15???????? 8d953cfeffff b9???????? }
            // n = 6, score = 1300
            //   ffb530feffff         | push                dword ptr [ebp - 0x1d0]
            //   ff15????????         |                     
            //   ffb530feffff         | push                dword ptr [ebp - 0x1d0]
            //   ff15????????         |                     
            //   8d953cfeffff         | lea                 edx, dword ptr [ebp - 0x1c4]
            //   b9????????           |                     

        $sequence_8 = { 0ac0 75f1 8d040a 33c2 5b }
            // n = 5, score = 1300
            //   0ac0                 | or                  al, al
            //   75f1                 | jne                 0xfffffff3
            //   8d040a               | lea                 eax, dword ptr [edx + ecx]
            //   33c2                 | xor                 eax, edx
            //   5b                   | pop                 ebx

        $sequence_9 = { ff75ec ff15???????? 837df000 7614 6a02 ff75f0 }
            // n = 6, score = 1300
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff15????????         |                     
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0
            //   7614                 | jbe                 0x16
            //   6a02                 | push                2
            //   ff75f0               | push                dword ptr [ebp - 0x10]

    condition:
        7 of them and filesize < 221184
}