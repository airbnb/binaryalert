rule win_cohhoc_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.cohhoc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cohhoc"
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
        $sequence_0 = { 50 53 ff15???????? 53 6a00 ff15???????? 8bc6 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8bc6                 | mov                 eax, esi

        $sequence_1 = { 8816 b803000000 eb09 8a06 0ac2 8806 46 }
            // n = 7, score = 300
            //   8816                 | mov                 byte ptr [esi], dl
            //   b803000000           | mov                 eax, 3
            //   eb09                 | jmp                 0xb
            //   8a06                 | mov                 al, byte ptr [esi]
            //   0ac2                 | or                  al, dl
            //   8806                 | mov                 byte ptr [esi], al
            //   46                   | inc                 esi

        $sequence_2 = { 55 56 57 b9ff0e0000 33c0 8d7c2421 c644242000 }
            // n = 7, score = 300
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi
            //   b9ff0e0000           | mov                 ecx, 0xeff
            //   33c0                 | xor                 eax, eax
            //   8d7c2421             | lea                 edi, dword ptr [esp + 0x21]
            //   c644242000           | mov                 byte ptr [esp + 0x20], 0

        $sequence_3 = { 6a00 aa ff15???????? bf???????? 83c9ff 33c0 }
            // n = 6, score = 300
            //   6a00                 | push                0
            //   aa                   | stosb               byte ptr es:[edi], al
            //   ff15????????         |                     
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 6aff 52 53 53 ffd6 b911000000 33c0 }
            // n = 7, score = 300
            //   6aff                 | push                -1
            //   52                   | push                edx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   b911000000           | mov                 ecx, 0x11
            //   33c0                 | xor                 eax, eax

        $sequence_5 = { 75dc 33c0 eb05 1bc0 83d8ff 85c0 0f84ba000000 }
            // n = 7, score = 300
            //   75dc                 | jne                 0xffffffde
            //   33c0                 | xor                 eax, eax
            //   eb05                 | jmp                 7
            //   1bc0                 | sbb                 eax, eax
            //   83d8ff               | sbb                 eax, -1
            //   85c0                 | test                eax, eax
            //   0f84ba000000         | je                  0xc0

        $sequence_6 = { eb0a c7450402000000 89736c 85ff 7623 8bcf }
            // n = 6, score = 300
            //   eb0a                 | jmp                 0xc
            //   c7450402000000       | mov                 dword ptr [ebp + 4], 2
            //   89736c               | mov                 dword ptr [ebx + 0x6c], esi
            //   85ff                 | test                edi, edi
            //   7623                 | jbe                 0x25
            //   8bcf                 | mov                 ecx, edi

        $sequence_7 = { 51 c705????????02000000 e8???????? 83c420 33d2 }
            // n = 5, score = 300
            //   51                   | push                ecx
            //   c705????????02000000     |     
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20
            //   33d2                 | xor                 edx, edx

        $sequence_8 = { 8be9 e8???????? 6a0c e8???????? 83c404 }
            // n = 5, score = 300
            //   8be9                 | mov                 ebp, ecx
            //   e8????????           |                     
            //   6a0c                 | push                0xc
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_9 = { 57 33db b940000000 33c0 8d7c241d 885c241c f3ab }
            // n = 7, score = 300
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax
            //   8d7c241d             | lea                 edi, dword ptr [esp + 0x1d]
            //   885c241c             | mov                 byte ptr [esp + 0x1c], bl
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

    condition:
        7 of them and filesize < 253952
}