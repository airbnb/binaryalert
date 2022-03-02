rule win_kikothac_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.kikothac."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kikothac"
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
        $sequence_0 = { 53 ffd0 85c0 7519 56 b301 e8???????? }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   7519                 | jne                 0x1b
            //   56                   | push                esi
            //   b301                 | mov                 bl, 1
            //   e8????????           |                     

        $sequence_1 = { a1???????? 85c0 7560 6a07 e8???????? 83c404 a3???????? }
            // n = 7, score = 200
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7560                 | jne                 0x62
            //   6a07                 | push                7
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   a3????????           |                     

        $sequence_2 = { 8db424d5adfa4d 660fce 60 c744242000000000 660fbef0 8b3424 e8???????? }
            // n = 7, score = 200
            //   8db424d5adfa4d       | lea                 esi, dword ptr [esp + 0x4dfaadd5]
            //   660fce               | bswap               si
            //   60                   | pushal              
            //   c744242000000000     | mov                 dword ptr [esp + 0x20], 0
            //   660fbef0             | movsx               si, al
            //   8b3424               | mov                 esi, dword ptr [esp]
            //   e8????????           |                     

        $sequence_3 = { 8d95dcfbffff e8???????? 83c40c 8d95dcfbffff 52 ff15???????? }
            // n = 6, score = 200
            //   8d95dcfbffff         | lea                 edx, dword ptr [ebp - 0x424]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d95dcfbffff         | lea                 edx, dword ptr [ebp - 0x424]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_4 = { 8d4f40 6689df 660fbefa 98 6619df 29d1 }
            // n = 6, score = 200
            //   8d4f40               | lea                 ecx, dword ptr [edi + 0x40]
            //   6689df               | mov                 di, bx
            //   660fbefa             | movsx               di, dl
            //   98                   | cwde                
            //   6619df               | sbb                 di, bx
            //   29d1                 | sub                 ecx, edx

        $sequence_5 = { 57 50 ff15???????? 85c0 7410 56 68???????? }
            // n = 7, score = 200
            //   57                   | push                edi
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7410                 | je                  0x12
            //   56                   | push                esi
            //   68????????           |                     

        $sequence_6 = { c0da02 f5 8b1407 f8 a876 }
            // n = 5, score = 200
            //   c0da02               | rcr                 dl, 2
            //   f5                   | cmc                 
            //   8b1407               | mov                 edx, dword ptr [edi + eax]
            //   f8                   | clc                 
            //   a876                 | test                al, 0x76

        $sequence_7 = { 8b75fc 83feff 0f8498000000 6a40 8d4da0 57 51 }
            // n = 7, score = 200
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   83feff               | cmp                 esi, -1
            //   0f8498000000         | je                  0x9e
            //   6a40                 | push                0x40
            //   8d4da0               | lea                 ecx, dword ptr [ebp - 0x60]
            //   57                   | push                edi
            //   51                   | push                ecx

        $sequence_8 = { 8b4df4 668b55f8 8908 a1???????? 8a4dfa }
            // n = 5, score = 200
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   668b55f8             | mov                 dx, word ptr [ebp - 8]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   a1????????           |                     
            //   8a4dfa               | mov                 cl, byte ptr [ebp - 6]

        $sequence_9 = { 9c 8d64242c e9???????? f6dc 8b4500 d2d6 }
            // n = 6, score = 200
            //   9c                   | pushfd              
            //   8d64242c             | lea                 esp, dword ptr [esp + 0x2c]
            //   e9????????           |                     
            //   f6dc                 | neg                 ah
            //   8b4500               | mov                 eax, dword ptr [ebp]
            //   d2d6                 | rcl                 dh, cl

    condition:
        7 of them and filesize < 581632
}