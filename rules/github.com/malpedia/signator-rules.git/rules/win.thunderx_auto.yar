rule win_thunderx_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.thunderx."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thunderx"
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
        $sequence_0 = { a3???????? 8b4104 a3???????? 8b4108 }
            // n = 4, score = 200
            //   a3????????           |                     
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   a3????????           |                     
            //   8b4108               | mov                 eax, dword ptr [ecx + 8]

        $sequence_1 = { ff15???????? 51 50 8d4dd4 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8d4dd4               | lea                 ecx, dword ptr [ebp - 0x2c]

        $sequence_2 = { e8???????? e8???????? 8d4c240c e8???????? }
            // n = 4, score = 200
            //   e8????????           |                     
            //   e8????????           |                     
            //   8d4c240c             | lea                 ecx, dword ptr [esp + 0xc]
            //   e8????????           |                     

        $sequence_3 = { 8845d5 8b45b0 895db8 c745d801000000 8b0485701b4200 8945d0 81f9e9fd0000 }
            // n = 7, score = 200
            //   8845d5               | mov                 byte ptr [ebp - 0x2b], al
            //   8b45b0               | mov                 eax, dword ptr [ebp - 0x50]
            //   895db8               | mov                 dword ptr [ebp - 0x48], ebx
            //   c745d801000000       | mov                 dword ptr [ebp - 0x28], 1
            //   8b0485701b4200       | mov                 eax, dword ptr [eax*4 + 0x421b70]
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   81f9e9fd0000         | cmp                 ecx, 0xfde9

        $sequence_4 = { 59 1adb 59 fec3 eb02 32db e8???????? }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   1adb                 | sbb                 bl, bl
            //   59                   | pop                 ecx
            //   fec3                 | inc                 bl
            //   eb02                 | jmp                 4
            //   32db                 | xor                 bl, bl
            //   e8????????           |                     

        $sequence_5 = { 8d4d90 e8???????? 833d????????00 0f8420040000 a1???????? 8d4ded 6a0a }
            // n = 7, score = 200
            //   8d4d90               | lea                 ecx, dword ptr [ebp - 0x70]
            //   e8????????           |                     
            //   833d????????00       |                     
            //   0f8420040000         | je                  0x426
            //   a1????????           |                     
            //   8d4ded               | lea                 ecx, dword ptr [ebp - 0x13]
            //   6a0a                 | push                0xa

        $sequence_6 = { e8???????? 8d4c243c e8???????? ba???????? 8d4c2424 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   8d4c243c             | lea                 ecx, dword ptr [esp + 0x3c]
            //   e8????????           |                     
            //   ba????????           |                     
            //   8d4c2424             | lea                 ecx, dword ptr [esp + 0x24]

        $sequence_7 = { 03c9 e8???????? 5d c20400 e8???????? cc }
            // n = 6, score = 200
            //   03c9                 | add                 ecx, ecx
            //   e8????????           |                     
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   e8????????           |                     
            //   cc                   | int3                

        $sequence_8 = { 33c0 40 e9???????? 8365c000 c745c47c964000 a1???????? 8d4dc0 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   e9????????           |                     
            //   8365c000             | and                 dword ptr [ebp - 0x40], 0
            //   c745c47c964000       | mov                 dword ptr [ebp - 0x3c], 0x40967c
            //   a1????????           |                     
            //   8d4dc0               | lea                 ecx, dword ptr [ebp - 0x40]

        $sequence_9 = { c3 55 8bec 51 8b4214 53 8b5a10 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   8b4214               | mov                 eax, dword ptr [edx + 0x14]
            //   53                   | push                ebx
            //   8b5a10               | mov                 ebx, dword ptr [edx + 0x10]

    condition:
        7 of them and filesize < 319488
}