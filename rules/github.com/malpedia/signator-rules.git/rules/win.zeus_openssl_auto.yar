rule win_zeus_openssl_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.zeus_openssl."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeus_openssl"
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
        $sequence_0 = { d3e0 4b 47 83c608 03d0 895dfc 8955f8 }
            // n = 7, score = 1200
            //   d3e0                 | shl                 eax, cl
            //   4b                   | dec                 ebx
            //   47                   | inc                 edi
            //   83c608               | add                 esi, 8
            //   03d0                 | add                 edx, eax
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   8955f8               | mov                 dword ptr [ebp - 8], edx

        $sequence_1 = { 50 8bf2 89852cfdffff c78530fdffff01000100 ff15???????? 85c0 0f84bf000000 }
            // n = 7, score = 1200
            //   50                   | push                eax
            //   8bf2                 | mov                 esi, edx
            //   89852cfdffff         | mov                 dword ptr [ebp - 0x2d4], eax
            //   c78530fdffff01000100     | mov    dword ptr [ebp - 0x2d0], 0x10001
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84bf000000         | je                  0xc5

        $sequence_2 = { e8???????? 8d4df4 8bf0 e8???????? eb10 f7de 1bf6 }
            // n = 7, score = 1200
            //   e8????????           |                     
            //   8d4df4               | lea                 ecx, dword ptr [ebp - 0xc]
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   eb10                 | jmp                 0x12
            //   f7de                 | neg                 esi
            //   1bf6                 | sbb                 esi, esi

        $sequence_3 = { 8b4708 894710 8b06 83781000 0f850ffdffff 5f 5e }
            // n = 7, score = 1200
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   894710               | mov                 dword ptr [edi + 0x10], eax
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   83781000             | cmp                 dword ptr [eax + 0x10], 0
            //   0f850ffdffff         | jne                 0xfffffd15
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_4 = { 85ff 7507 5f 8d46fd 5e }
            // n = 5, score = 1200
            //   85ff                 | test                edi, edi
            //   7507                 | jne                 9
            //   5f                   | pop                 edi
            //   8d46fd               | lea                 eax, dword ptr [esi - 3]
            //   5e                   | pop                 esi

        $sequence_5 = { 897dd0 8945d4 33db e8???????? 391d???????? }
            // n = 5, score = 1200
            //   897dd0               | mov                 dword ptr [ebp - 0x30], edi
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   33db                 | xor                 ebx, ebx
            //   e8????????           |                     
            //   391d????????         |                     

        $sequence_6 = { 8ae2 80e4f0 80fc70 742c 8ac2 }
            // n = 5, score = 1200
            //   8ae2                 | mov                 ah, dl
            //   80e4f0               | and                 ah, 0xf0
            //   80fc70               | cmp                 ah, 0x70
            //   742c                 | je                  0x2e
            //   8ac2                 | mov                 al, dl

        $sequence_7 = { 837d1008 0f8580010000 8d43f8 83f807 0f8774010000 83f909 0f876b010000 }
            // n = 7, score = 1200
            //   837d1008             | cmp                 dword ptr [ebp + 0x10], 8
            //   0f8580010000         | jne                 0x186
            //   8d43f8               | lea                 eax, dword ptr [ebx - 8]
            //   83f807               | cmp                 eax, 7
            //   0f8774010000         | ja                  0x17a
            //   83f909               | cmp                 ecx, 9
            //   0f876b010000         | ja                  0x171

        $sequence_8 = { 8d4df4 51 6a40 50 57 ff15???????? 85c0 }
            // n = 7, score = 1200
            //   8d4df4               | lea                 ecx, dword ptr [ebp - 0xc]
            //   51                   | push                ecx
            //   6a40                 | push                0x40
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 3c05 eb11 8a45fd c645fb03 }
            // n = 4, score = 1200
            //   3c05                 | cmp                 al, 5
            //   eb11                 | jmp                 0x13
            //   8a45fd               | mov                 al, byte ptr [ebp - 3]
            //   c645fb03             | mov                 byte ptr [ebp - 5], 3

    condition:
        7 of them and filesize < 4546560
}