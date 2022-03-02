rule win_mimikatz_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.mimikatz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mimikatz"
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
        $sequence_0 = { 83f8ff 750e ff15???????? c7002a000000 }
            // n = 4, score = 300
            //   83f8ff               | cmp                 eax, -1
            //   750e                 | jne                 0x10
            //   ff15????????         |                     
            //   c7002a000000         | mov                 dword ptr [eax], 0x2a

        $sequence_1 = { f7f1 85d2 7406 2bca }
            // n = 4, score = 300
            //   f7f1                 | div                 ecx
            //   85d2                 | test                edx, edx
            //   7406                 | je                  8
            //   2bca                 | sub                 ecx, edx

        $sequence_2 = { c3 81f998000000 7410 81f996000000 7408 }
            // n = 5, score = 200
            //   c3                   | ret                 
            //   81f998000000         | cmp                 ecx, 0x98
            //   7410                 | je                  0x12
            //   81f996000000         | cmp                 ecx, 0x96
            //   7408                 | je                  0xa

        $sequence_3 = { e8???????? 837c246000 0f849c000000 85f6 7541 8b05???????? 3d401f0000 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   837c246000           | cmp                 dword ptr [esp + 0x60], 0
            //   0f849c000000         | je                  0xa2
            //   85f6                 | test                esi, esi
            //   7541                 | jne                 0x43
            //   8b05????????         |                     
            //   3d401f0000           | cmp                 eax, 0x1f40

        $sequence_4 = { e8???????? eb2d 81fa0e030980 750e }
            // n = 4, score = 200
            //   e8????????           |                     
            //   eb2d                 | jmp                 0x2f
            //   81fa0e030980         | cmp                 edx, 0x8009030e
            //   750e                 | jne                 0x10

        $sequence_5 = { 83f812 72f1 33c0 c3 }
            // n = 4, score = 200
            //   83f812               | cmp                 eax, 0x12
            //   72f1                 | jb                  0xfffffff3
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 

        $sequence_6 = { 2bc1 85c9 7403 83c008 }
            // n = 4, score = 200
            //   2bc1                 | sub                 eax, ecx
            //   85c9                 | test                ecx, ecx
            //   7403                 | je                  5
            //   83c008               | add                 eax, 8

        $sequence_7 = { eb16 83780802 7510 0fb75010 }
            // n = 4, score = 200
            //   eb16                 | jmp                 0x18
            //   83780802             | cmp                 dword ptr [eax + 8], 2
            //   7510                 | jne                 0x12
            //   0fb75010             | movzx               edx, word ptr [eax + 0x10]

        $sequence_8 = { 6683f83f 7607 32c0 e9???????? }
            // n = 4, score = 200
            //   6683f83f             | cmp                 ax, 0x3f
            //   7607                 | jbe                 9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     

        $sequence_9 = { 66894108 33c0 39410c 740b }
            // n = 4, score = 200
            //   66894108             | mov                 word ptr [ecx + 8], ax
            //   33c0                 | xor                 eax, eax
            //   39410c               | cmp                 dword ptr [ecx + 0xc], eax
            //   740b                 | je                  0xd

        $sequence_10 = { e8???????? 8bf8 89442458 89442454 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   89442458             | mov                 dword ptr [esp + 0x58], eax
            //   89442454             | mov                 dword ptr [esp + 0x54], eax

        $sequence_11 = { ff15???????? 85c0 0f84ce000000 8d4510 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84ce000000         | je                  0xd4
            //   8d4510               | lea                 eax, dword ptr [ebp + 0x10]

        $sequence_12 = { e8???????? 85db 0f8408010000 03ed }
            // n = 4, score = 200
            //   e8????????           |                     
            //   85db                 | test                ebx, ebx
            //   0f8408010000         | je                  0x10e
            //   03ed                 | add                 ebp, ebp

        $sequence_13 = { 3c02 7207 e8???????? eb10 }
            // n = 4, score = 200
            //   3c02                 | cmp                 al, 2
            //   7207                 | jb                  9
            //   e8????????           |                     
            //   eb10                 | jmp                 0x12

        $sequence_14 = { e8???????? 83c40c 03f3 8bc7 8b550c }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   03f3                 | add                 esi, ebx
            //   8bc7                 | mov                 eax, edi
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

        $sequence_15 = { c1f805 c1e606 033485c0e84600 8b45f8 8b00 8906 8b45fc }
            // n = 7, score = 100
            //   c1f805               | sar                 eax, 5
            //   c1e606               | shl                 esi, 6
            //   033485c0e84600       | add                 esi, dword ptr [eax*4 + 0x46e8c0]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_16 = { 80e20f c0e104 32d1 4b 885509 88450a 85db }
            // n = 7, score = 100
            //   80e20f               | and                 dl, 0xf
            //   c0e104               | shl                 cl, 4
            //   32d1                 | xor                 dl, cl
            //   4b                   | dec                 ebx
            //   885509               | mov                 byte ptr [ebp + 9], dl
            //   88450a               | mov                 byte ptr [ebp + 0xa], al
            //   85db                 | test                ebx, ebx

        $sequence_17 = { 2bfe 90 41 81e1ff000000 8a91b0e74600 }
            // n = 5, score = 100
            //   2bfe                 | sub                 edi, esi
            //   90                   | nop                 
            //   41                   | inc                 ecx
            //   81e1ff000000         | and                 ecx, 0xff
            //   8a91b0e74600         | mov                 dl, byte ptr [ecx + 0x46e7b0]

        $sequence_18 = { 85db 0f84b9000000 83fb04 7d17 b904000000 2bcb }
            // n = 6, score = 100
            //   85db                 | test                ebx, ebx
            //   0f84b9000000         | je                  0xbf
            //   83fb04               | cmp                 ebx, 4
            //   7d17                 | jge                 0x19
            //   b904000000           | mov                 ecx, 4
            //   2bcb                 | sub                 ecx, ebx

        $sequence_19 = { 33c0 8b4d08 3b0cc5087a4000 740a }
            // n = 4, score = 100
            //   33c0                 | xor                 eax, eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   3b0cc5087a4000       | cmp                 ecx, dword ptr [eax*8 + 0x407a08]
            //   740a                 | je                  0xc

        $sequence_20 = { 8d34f530d94600 391e 7404 8bc7 eb6d 6a18 e8???????? }
            // n = 7, score = 100
            //   8d34f530d94600       | lea                 esi, dword ptr [esi*8 + 0x46d930]
            //   391e                 | cmp                 dword ptr [esi], ebx
            //   7404                 | je                  6
            //   8bc7                 | mov                 eax, edi
            //   eb6d                 | jmp                 0x6f
            //   6a18                 | push                0x18
            //   e8????????           |                     

        $sequence_21 = { 83c404 85c0 7510 8a45ff 3c2b }
            // n = 5, score = 100
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12
            //   8a45ff               | mov                 al, byte ptr [ebp - 1]
            //   3c2b                 | cmp                 al, 0x2b

    condition:
        7 of them and filesize < 1642496
}