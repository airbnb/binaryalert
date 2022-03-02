rule win_citadel_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.citadel."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.citadel"
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
        $sequence_0 = { eb0e 6800800000 53 57 56 }
            // n = 5, score = 4900
            //   eb0e                 | jmp                 0x10
            //   6800800000           | push                0x8000
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_1 = { e8???????? 8bf0 89742410 85f6 7507 32c0 e9???????? }
            // n = 7, score = 4800
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   89742410             | mov                 dword ptr [esp + 0x10], esi
            //   85f6                 | test                esi, esi
            //   7507                 | jne                 9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     

        $sequence_2 = { e8???????? 84c0 7407 c644240f01 eb2f 8bcb e8???????? }
            // n = 7, score = 4800
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7407                 | je                  9
            //   c644240f01           | mov                 byte ptr [esp + 0xf], 1
            //   eb2f                 | jmp                 0x31
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_3 = { e8???????? 8844240f 57 e8???????? ff74241c }
            // n = 5, score = 4800
            //   e8????????           |                     
            //   8844240f             | mov                 byte ptr [esp + 0xf], al
            //   57                   | push                edi
            //   e8????????           |                     
            //   ff74241c             | push                dword ptr [esp + 0x1c]

        $sequence_4 = { e8???????? ff74241c e8???????? 807c240f00 750e }
            // n = 5, score = 4800
            //   e8????????           |                     
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   e8????????           |                     
            //   807c240f00           | cmp                 byte ptr [esp + 0xf], 0
            //   750e                 | jne                 0x10

        $sequence_5 = { e8???????? 8b4c2414 8d543e01 e8???????? }
            // n = 4, score = 4800
            //   e8????????           |                     
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8d543e01             | lea                 edx, dword ptr [esi + edi + 1]
            //   e8????????           |                     

        $sequence_6 = { e8???????? 8bf0 e8???????? 8b7c2418 8d743201 c60600 6a02 }
            // n = 7, score = 4800
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]
            //   8d743201             | lea                 esi, dword ptr [edx + esi + 1]
            //   c60600               | mov                 byte ptr [esi], 0
            //   6a02                 | push                2

        $sequence_7 = { e8???????? 8bf0 85f6 75c9 eb0d 53 83c8ff }
            // n = 7, score = 4800
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   75c9                 | jne                 0xffffffcb
            //   eb0d                 | jmp                 0xf
            //   53                   | push                ebx
            //   83c8ff               | or                  eax, 0xffffffff

        $sequence_8 = { 8b4e10 8a5e14 fec8 32d0 }
            // n = 4, score = 3700
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   8a5e14               | mov                 bl, byte ptr [esi + 0x14]
            //   fec8                 | dec                 al
            //   32d0                 | xor                 dl, al

        $sequence_9 = { ffd0 8807 fe45ff 8a45ff 3a06 }
            // n = 5, score = 3700
            //   ffd0                 | call                eax
            //   8807                 | mov                 byte ptr [edi], al
            //   fe45ff               | inc                 byte ptr [ebp - 1]
            //   8a45ff               | mov                 al, byte ptr [ebp - 1]
            //   3a06                 | cmp                 al, byte ptr [esi]

        $sequence_10 = { 73fa 0fb6c0 8b44c104 e9???????? d0e9 }
            // n = 5, score = 3700
            //   73fa                 | jae                 0xfffffffc
            //   0fb6c0               | movzx               eax, al
            //   8b44c104             | mov                 eax, dword ptr [ecx + eax*8 + 4]
            //   e9????????           |                     
            //   d0e9                 | shr                 cl, 1

        $sequence_11 = { 57 8bf8 c745f801000000 85f6 0f842b010000 837e1000 }
            // n = 6, score = 3700
            //   57                   | push                edi
            //   8bf8                 | mov                 edi, eax
            //   c745f801000000       | mov                 dword ptr [ebp - 8], 1
            //   85f6                 | test                esi, esi
            //   0f842b010000         | je                  0x131
            //   837e1000             | cmp                 dword ptr [esi + 0x10], 0

        $sequence_12 = { b001 eb30 d0e8 3ac3 73fa 0fb6c0 }
            // n = 6, score = 3700
            //   b001                 | mov                 al, 1
            //   eb30                 | jmp                 0x32
            //   d0e8                 | shr                 al, 1
            //   3ac3                 | cmp                 al, bl
            //   73fa                 | jae                 0xfffffffc
            //   0fb6c0               | movzx               eax, al

        $sequence_13 = { 32d0 8ac2 3245fe 85c9 7408 84db }
            // n = 6, score = 3700
            //   32d0                 | xor                 dl, al
            //   8ac2                 | mov                 al, dl
            //   3245fe               | xor                 al, byte ptr [ebp - 2]
            //   85c9                 | test                ecx, ecx
            //   7408                 | je                  0xa
            //   84db                 | test                bl, bl

        $sequence_14 = { 763c 8a06 2a45ff 8a5602 8b4e10 }
            // n = 5, score = 3700
            //   763c                 | jbe                 0x3e
            //   8a06                 | mov                 al, byte ptr [esi]
            //   2a45ff               | sub                 al, byte ptr [ebp - 1]
            //   8a5602               | mov                 dl, byte ptr [esi + 2]
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]

        $sequence_15 = { 0f842b010000 837e1000 0f8421010000 807e1400 }
            // n = 4, score = 3700
            //   0f842b010000         | je                  0x131
            //   837e1000             | cmp                 dword ptr [esi + 0x10], 0
            //   0f8421010000         | je                  0x127
            //   807e1400             | cmp                 byte ptr [esi + 0x14], 0

    condition:
        7 of them and filesize < 1236992
}