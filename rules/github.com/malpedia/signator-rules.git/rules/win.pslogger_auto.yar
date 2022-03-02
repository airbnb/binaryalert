rule win_pslogger_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.pslogger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pslogger"
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
        $sequence_0 = { 48895c2408 57 4883ec20 488d1d73fa0000 bf0a000000 488b0b }
            // n = 6, score = 200
            //   48895c2408           | dec                 esp
            //   57                   | lea                 esp, dword ptr [ecx + 8]
            //   4883ec20             | dec                 ebp
            //   488d1d73fa0000       | mov                 ebp, dword ptr [esp]
            //   bf0a000000           | jmp                 0x22
            //   488b0b               | dec                 esp

        $sequence_1 = { eb40 4c8d250dfd0000 488b0d???????? e9???????? 4c8d250afd0000 488b0d???????? }
            // n = 6, score = 200
            //   eb40                 | lea                 esp, dword ptr [0xfc74]
            //   4c8d250dfd0000       | mov                 edi, 1
            //   488b0d????????       |                     
            //   e9????????           |                     
            //   4c8d250afd0000       | xor                 edx, edx
            //   488b0d????????       |                     

        $sequence_2 = { 48897c2420 ff15???????? 48894330 4885c0 7522 }
            // n = 5, score = 200
            //   48897c2420           | dec                 eax
            //   ff15????????         |                     
            //   48894330             | mov                 dword ptr [esp + 0x20], edi
            //   4885c0               | dec                 eax
            //   7522                 | mov                 dword ptr [ebx + 0x30], eax

        $sequence_3 = { 488975e8 488b4d38 4885c9 7407 ff15???????? 90 488b4dc0 }
            // n = 7, score = 200
            //   488975e8             | mov                 eax, dword ptr [eax + edx*8 + 0x10]
            //   488b4d38             | mov                 dword ptr [ecx + 0x10], eax
            //   4885c9               | inc                 ecx
            //   7407                 | mov                 eax, dword ptr [eax + edx*8 + 0x14]
            //   ff15????????         |                     
            //   90                   | mov                 dword ptr [ecx + 0x14], eax
            //   488b4dc0             | dec                 eax

        $sequence_4 = { 4c8d6108 4d8b2c24 eb20 4c8d2574fc0000 488b0d???????? bf01000000 }
            // n = 6, score = 200
            //   4c8d6108             | mov                 dword ptr [ebp - 0x18], esi
            //   4d8b2c24             | dec                 eax
            //   eb20                 | mov                 ecx, dword ptr [ebp + 0x38]
            //   4c8d2574fc0000       | dec                 eax
            //   488b0d????????       |                     
            //   bf01000000           | test                ecx, ecx

        $sequence_5 = { 84c0 75e8 33c0 4883c9ff 488dbc2470020000 }
            // n = 5, score = 200
            //   84c0                 | inc                 ecx
            //   75e8                 | mov                 eax, 0x101
            //   33c0                 | dec                 esp
            //   4883c9ff             | lea                 edx, dword ptr [ebp + ebp*2]
            //   488dbc2470020000     | dec                 esp

        $sequence_6 = { 33d2 41b801010000 e8???????? 4c8d546d00 4c8d1d5c0e0100 }
            // n = 5, score = 200
            //   33d2                 | je                  0xc
            //   41b801010000         | nop                 
            //   e8????????           |                     
            //   4c8d546d00           | dec                 eax
            //   4c8d1d5c0e0100       | mov                 ecx, dword ptr [ebp - 0x40]

        $sequence_7 = { 418b44d010 894110 418b44d014 894114 }
            // n = 4, score = 200
            //   418b44d010           | dec                 eax
            //   894110               | test                eax, eax
            //   418b44d014           | jne                 0x27
            //   894114               | inc                 ecx

        $sequence_8 = { e9???????? 3dfafe0000 0f82a6000000 83be78af060000 0f8499000000 6800800000 8d86702f0200 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   3dfafe0000           | cmp                 eax, 0xfefa
            //   0f82a6000000         | jb                  0xac
            //   83be78af060000       | cmp                 dword ptr [esi + 0x6af78], 0
            //   0f8499000000         | je                  0x9f
            //   6800800000           | push                0x8000
            //   8d86702f0200         | lea                 eax, dword ptr [esi + 0x22f70]

        $sequence_9 = { 7f05 83fb13 7e0a c786a4af0600287a4200 6a05 }
            // n = 5, score = 100
            //   7f05                 | jg                  7
            //   83fb13               | cmp                 ebx, 0x13
            //   7e0a                 | jle                 0xc
            //   c786a4af0600287a4200     | mov    dword ptr [esi + 0x6afa4], 0x427a28
            //   6a05                 | push                5

        $sequence_10 = { 83f826 7603 6a26 58 0fb60c85d64b4200 0fb63485d74b4200 8bf9 }
            // n = 7, score = 100
            //   83f826               | cmp                 eax, 0x26
            //   7603                 | jbe                 5
            //   6a26                 | push                0x26
            //   58                   | pop                 eax
            //   0fb60c85d64b4200     | movzx               ecx, byte ptr [eax*4 + 0x424bd6]
            //   0fb63485d74b4200     | movzx               esi, byte ptr [eax*4 + 0x424bd7]
            //   8bf9                 | mov                 edi, ecx

        $sequence_11 = { 7505 895344 eb28 83b95c03000000 }
            // n = 4, score = 100
            //   7505                 | jne                 7
            //   895344               | mov                 dword ptr [ebx + 0x44], edx
            //   eb28                 | jmp                 0x2a
            //   83b95c03000000       | cmp                 dword ptr [ecx + 0x35c], 0

        $sequence_12 = { 8d873e0c0000 b970000000 bb09000000 660f1f440000 668918 8d4004 66ff87f60f0000 }
            // n = 7, score = 100
            //   8d873e0c0000         | lea                 eax, dword ptr [edi + 0xc3e]
            //   b970000000           | mov                 ecx, 0x70
            //   bb09000000           | mov                 ebx, 9
            //   660f1f440000         | nop                 word ptr [eax + eax]
            //   668918               | mov                 word ptr [eax], bx
            //   8d4004               | lea                 eax, dword ptr [eax + 4]
            //   66ff87f60f0000       | inc                 word ptr [edi + 0xff6]

        $sequence_13 = { ffd6 8b4d14 8945fc 8901 8b4d10 8939 }
            // n = 6, score = 100
            //   ffd6                 | call                esi
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8939                 | mov                 dword ptr [ecx], edi

        $sequence_14 = { 6690 8b08 83b95c03000000 8d815c030000 75ef 89915c030000 }
            // n = 6, score = 100
            //   6690                 | nop                 
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   83b95c03000000       | cmp                 dword ptr [ecx + 0x35c], 0
            //   8d815c030000         | lea                 eax, dword ptr [ecx + 0x35c]
            //   75ef                 | jne                 0xfffffff1
            //   89915c030000         | mov                 dword ptr [ecx + 0x35c], edx

        $sequence_15 = { 8b5104 e8???????? 8b4f48 83c404 e8???????? 8b4f48 ba00000005 }
            // n = 7, score = 100
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   e8????????           |                     
            //   8b4f48               | mov                 ecx, dword ptr [edi + 0x48]
            //   83c404               | add                 esp, 4
            //   e8????????           |                     
            //   8b4f48               | mov                 ecx, dword ptr [edi + 0x48]
            //   ba00000005           | mov                 edx, 0x5000000

    condition:
        7 of them and filesize < 434176
}