rule win_crenufs_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.crenufs."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crenufs"
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
        $sequence_0 = { 3bc3 7402 8bf8 8a45f3 53 8d4dd0 8845d0 }
            // n = 7, score = 200
            //   3bc3                 | cmp                 eax, ebx
            //   7402                 | je                  4
            //   8bf8                 | mov                 edi, eax
            //   8a45f3               | mov                 al, byte ptr [ebp - 0xd]
            //   53                   | push                ebx
            //   8d4dd0               | lea                 ecx, dword ptr [ebp - 0x30]
            //   8845d0               | mov                 byte ptr [ebp - 0x30], al

        $sequence_1 = { 8b4758 85c0 7505 897758 }
            // n = 4, score = 200
            //   8b4758               | mov                 eax, dword ptr [edi + 0x58]
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   897758               | mov                 dword ptr [edi + 0x58], esi

        $sequence_2 = { 48 8944241c 75a8 8b742410 8b4c2420 }
            // n = 5, score = 200
            //   48                   | dec                 eax
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   75a8                 | jne                 0xffffffaa
            //   8b742410             | mov                 esi, dword ptr [esp + 0x10]
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]

        $sequence_3 = { 53 53 53 8b1d???????? 56 ffd3 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   56                   | push                esi
            //   ffd3                 | call                ebx

        $sequence_4 = { 6a40 8d45c0 6a00 50 e8???????? 8a85c1fcffff }
            // n = 6, score = 200
            //   6a40                 | push                0x40
            //   8d45c0               | lea                 eax, dword ptr [ebp - 0x40]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   8a85c1fcffff         | mov                 al, byte ptr [ebp - 0x33f]

        $sequence_5 = { ff15???????? 8b0d???????? c684243c04000001 8b11 8d4c2410 52 6a00 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   8b0d????????         |                     
            //   c684243c04000001     | mov                 byte ptr [esp + 0x43c], 1
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8d4c2410             | lea                 ecx, dword ptr [esp + 0x10]
            //   52                   | push                edx
            //   6a00                 | push                0

        $sequence_6 = { eb02 33c0 c20800 837c240400 7428 56 }
            // n = 6, score = 200
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   c20800               | ret                 8
            //   837c240400           | cmp                 dword ptr [esp + 4], 0
            //   7428                 | je                  0x2a
            //   56                   | push                esi

        $sequence_7 = { 0f842c010000 8b4304 6a00 6a00 }
            // n = 4, score = 200
            //   0f842c010000         | je                  0x132
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_8 = { 03ca 894c2438 3b4b18 740d 8b4c2454 c74118ccc74000 eb61 }
            // n = 7, score = 200
            //   03ca                 | add                 ecx, edx
            //   894c2438             | mov                 dword ptr [esp + 0x38], ecx
            //   3b4b18               | cmp                 ecx, dword ptr [ebx + 0x18]
            //   740d                 | je                  0xf
            //   8b4c2454             | mov                 ecx, dword ptr [esp + 0x54]
            //   c74118ccc74000       | mov                 dword ptr [ecx + 0x18], 0x40c7cc
            //   eb61                 | jmp                 0x63

        $sequence_9 = { 89742434 33db 8b442420 8b4c2424 40 3bc1 89442420 }
            // n = 7, score = 200
            //   89742434             | mov                 dword ptr [esp + 0x34], esi
            //   33db                 | xor                 ebx, ebx
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   40                   | inc                 eax
            //   3bc1                 | cmp                 eax, ecx
            //   89442420             | mov                 dword ptr [esp + 0x20], eax

    condition:
        7 of them and filesize < 106496
}