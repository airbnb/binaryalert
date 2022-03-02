rule win_glooxmail_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.glooxmail."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glooxmail"
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
        $sequence_0 = { 85c0 7413 53 ff35???????? ff15???????? 891d???????? be???????? }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15
            //   53                   | push                ebx
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   891d????????         |                     
            //   be????????           |                     

        $sequence_1 = { e9???????? 8d4d1c e9???????? 8d4dd8 e9???????? 8d4d38 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d4d1c               | lea                 ecx, dword ptr [ebp + 0x1c]
            //   e9????????           |                     
            //   8d4dd8               | lea                 ecx, dword ptr [ebp - 0x28]
            //   e9????????           |                     
            //   8d4d38               | lea                 ecx, dword ptr [ebp + 0x38]
            //   e9????????           |                     

        $sequence_2 = { 8d4d80 e9???????? 8d4dd0 e9???????? 8d4d9c e9???????? 8b45c0 }
            // n = 7, score = 100
            //   8d4d80               | lea                 ecx, dword ptr [ebp - 0x80]
            //   e9????????           |                     
            //   8d4dd0               | lea                 ecx, dword ptr [ebp - 0x30]
            //   e9????????           |                     
            //   8d4d9c               | lea                 ecx, dword ptr [ebp - 0x64]
            //   e9????????           |                     
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]

        $sequence_3 = { 8b45e4 83e820 8d8ec0000000 7413 83e860 7407 }
            // n = 6, score = 100
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   83e820               | sub                 eax, 0x20
            //   8d8ec0000000         | lea                 ecx, dword ptr [esi + 0xc0]
            //   7413                 | je                  0x15
            //   83e860               | sub                 eax, 0x60
            //   7407                 | je                  9

        $sequence_4 = { 51 8d4db4 c645fc0c 8b06 51 8bce ff5050 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8d4db4               | lea                 ecx, dword ptr [ebp - 0x4c]
            //   c645fc0c             | mov                 byte ptr [ebp - 4], 0xc
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   51                   | push                ecx
            //   8bce                 | mov                 ecx, esi
            //   ff5050               | call                dword ptr [eax + 0x50]

        $sequence_5 = { e9???????? 8d4d9c e9???????? 8b542408 8d825cffffff 8b8a58ffffff 33c8 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d4d9c               | lea                 ecx, dword ptr [ebp - 0x64]
            //   e9????????           |                     
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   8d825cffffff         | lea                 eax, dword ptr [edx - 0xa4]
            //   8b8a58ffffff         | mov                 ecx, dword ptr [edx - 0xa8]
            //   33c8                 | xor                 ecx, eax

        $sequence_6 = { 83c40c 6bc930 8975e0 8db130f74400 8975e4 eb2a 8a4601 }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   6bc930               | imul                ecx, ecx, 0x30
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   8db130f74400         | lea                 esi, dword ptr [ecx + 0x44f730]
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   eb2a                 | jmp                 0x2c
            //   8a4601               | mov                 al, byte ptr [esi + 1]

        $sequence_7 = { 3bc3 743d 68???????? 8d8c24fc010000 e8???????? 8b442420 05bc000000 }
            // n = 7, score = 100
            //   3bc3                 | cmp                 eax, ebx
            //   743d                 | je                  0x3f
            //   68????????           |                     
            //   8d8c24fc010000       | lea                 ecx, dword ptr [esp + 0x1fc]
            //   e8????????           |                     
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   05bc000000           | add                 eax, 0xbc

        $sequence_8 = { 8b06 51 8bce ff5010 57 53 8d8dccfeffff }
            // n = 7, score = 100
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   51                   | push                ecx
            //   8bce                 | mov                 ecx, esi
            //   ff5010               | call                dword ptr [eax + 0x10]
            //   57                   | push                edi
            //   53                   | push                ebx
            //   8d8dccfeffff         | lea                 ecx, dword ptr [ebp - 0x134]

        $sequence_9 = { 83a570fffffffe 8d4d9c e9???????? c3 8b8570ffffff }
            // n = 5, score = 100
            //   83a570fffffffe       | and                 dword ptr [ebp - 0x90], 0xfffffffe
            //   8d4d9c               | lea                 ecx, dword ptr [ebp - 0x64]
            //   e9????????           |                     
            //   c3                   | ret                 
            //   8b8570ffffff         | mov                 eax, dword ptr [ebp - 0x90]

    condition:
        7 of them and filesize < 761856
}