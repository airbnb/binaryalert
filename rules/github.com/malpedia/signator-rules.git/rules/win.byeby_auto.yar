rule win_byeby_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.byeby."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.byeby"
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
        $sequence_0 = { 81ff12030900 7414 81ff18030980 740c 81ff20030900 0f8505020000 }
            // n = 6, score = 100
            //   81ff12030900         | cmp                 edi, 0x90312
            //   7414                 | je                  0x16
            //   81ff18030980         | cmp                 edi, 0x80090318
            //   740c                 | je                  0xe
            //   81ff20030900         | cmp                 edi, 0x90320
            //   0f8505020000         | jne                 0x20b

        $sequence_1 = { 8d442430 50 6805100000 68ffff0000 }
            // n = 4, score = 100
            //   8d442430             | lea                 eax, dword ptr [esp + 0x30]
            //   50                   | push                eax
            //   6805100000           | push                0x1005
            //   68ffff0000           | push                0xffff

        $sequence_2 = { 50 ff15???????? 50 8d842448060000 50 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8d842448060000       | lea                 eax, dword ptr [esp + 0x648]
            //   50                   | push                eax

        $sequence_3 = { 8d7f08 8b048d78000110 ffe0 f7c703000000 7515 c1e902 }
            // n = 6, score = 100
            //   8d7f08               | lea                 edi, dword ptr [edi + 8]
            //   8b048d78000110       | mov                 eax, dword ptr [ecx*4 + 0x10010078]
            //   ffe0                 | jmp                 eax
            //   f7c703000000         | test                edi, 3
            //   7515                 | jne                 0x17
            //   c1e902               | shr                 ecx, 2

        $sequence_4 = { 8bf1 50 ff15???????? 6803050000 8d85c1f9ffff c685c0f9ffff00 6a00 }
            // n = 7, score = 100
            //   8bf1                 | mov                 esi, ecx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6803050000           | push                0x503
            //   8d85c1f9ffff         | lea                 eax, dword ptr [ebp - 0x63f]
            //   c685c0f9ffff00       | mov                 byte ptr [ebp - 0x640], 0
            //   6a00                 | push                0

        $sequence_5 = { 8b4e68 85c9 7577 81ff12030900 0f85cd000000 85c9 }
            // n = 6, score = 100
            //   8b4e68               | mov                 ecx, dword ptr [esi + 0x68]
            //   85c9                 | test                ecx, ecx
            //   7577                 | jne                 0x79
            //   81ff12030900         | cmp                 edi, 0x90312
            //   0f85cd000000         | jne                 0xd3
            //   85c9                 | test                ecx, ecx

        $sequence_6 = { 0f847b020000 6a00 8d442460 c744246001000000 }
            // n = 4, score = 100
            //   0f847b020000         | je                  0x281
            //   6a00                 | push                0
            //   8d442460             | lea                 eax, dword ptr [esp + 0x60]
            //   c744246001000000     | mov                 dword ptr [esp + 0x60], 1

        $sequence_7 = { 83c40c 85c0 0f85db000000 6a40 }
            // n = 4, score = 100
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f85db000000         | jne                 0xe1
            //   6a40                 | push                0x40

        $sequence_8 = { 8d8424f8060000 50 57 ff15???????? 85c0 75a3 83ceff }
            // n = 7, score = 100
            //   8d8424f8060000       | lea                 eax, dword ptr [esp + 0x6f8]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   75a3                 | jne                 0xffffffa5
            //   83ceff               | or                  esi, 0xffffffff

        $sequence_9 = { 8945e0 8bdf 83e31f c1e306 8b048518ab0110 0fbe440304 83e001 }
            // n = 7, score = 100
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8bdf                 | mov                 ebx, edi
            //   83e31f               | and                 ebx, 0x1f
            //   c1e306               | shl                 ebx, 6
            //   8b048518ab0110       | mov                 eax, dword ptr [eax*4 + 0x1001ab18]
            //   0fbe440304           | movsx               eax, byte ptr [ebx + eax + 4]
            //   83e001               | and                 eax, 1

    condition:
        7 of them and filesize < 253952
}