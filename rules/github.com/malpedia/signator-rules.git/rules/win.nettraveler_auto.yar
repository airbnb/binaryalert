rule win_nettraveler_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.nettraveler."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nettraveler"
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
        $sequence_0 = { 56 8d850cfcffff 53 50 8975e0 e8???????? }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8d850cfcffff         | lea                 eax, dword ptr [ebp - 0x3f4]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   e8????????           |                     

        $sequence_1 = { ab ab 33c0 8d7dd1 885dd0 6a08 }
            // n = 6, score = 100
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   33c0                 | xor                 eax, eax
            //   8d7dd1               | lea                 edi, dword ptr [ebp - 0x2f]
            //   885dd0               | mov                 byte ptr [ebp - 0x30], bl
            //   6a08                 | push                8

        $sequence_2 = { 6a0a ff15???????? 68???????? 895de8 ff15???????? 68???????? }
            // n = 6, score = 100
            //   6a0a                 | push                0xa
            //   ff15????????         |                     
            //   68????????           |                     
            //   895de8               | mov                 dword ptr [ebp - 0x18], ebx
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_3 = { ffd6 50 ff15???????? 895dfc ff7508 ff15???????? ff75ec }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   ff15????????         |                     
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   ff75ec               | push                dword ptr [ebp - 0x14]

        $sequence_4 = { 8d8764910010 807c1dc400 7404 8b1a 091e }
            // n = 5, score = 100
            //   8d8764910010         | lea                 eax, dword ptr [edi + 0x10009164]
            //   807c1dc400           | cmp                 byte ptr [ebp + ebx - 0x3c], 0
            //   7404                 | je                  6
            //   8b1a                 | mov                 ebx, dword ptr [edx]
            //   091e                 | or                  dword ptr [esi], ebx

        $sequence_5 = { 50 8d850cfcffff 50 ff15???????? 85c0 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8d850cfcffff         | lea                 eax, dword ptr [ebp - 0x3f4]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_6 = { 50 ff75fc ff750c ff7508 e8???????? 83c428 395dfc }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   83c428               | add                 esp, 0x28
            //   395dfc               | cmp                 dword ptr [ebp - 4], ebx

        $sequence_7 = { 25003f0000 83e13f 0bf0 83c204 0bf1 8932 83c204 }
            // n = 7, score = 100
            //   25003f0000           | and                 eax, 0x3f00
            //   83e13f               | and                 ecx, 0x3f
            //   0bf0                 | or                  esi, eax
            //   83c204               | add                 edx, 4
            //   0bf1                 | or                  esi, ecx
            //   8932                 | mov                 dword ptr [edx], esi
            //   83c204               | add                 edx, 4

        $sequence_8 = { e8???????? ff7514 8d45f4 50 8d45dc 50 ff7508 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   8d45dc               | lea                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_9 = { dc0d???????? dd1c24 50 51 8d850cf1ffff 68???????? 50 }
            // n = 7, score = 100
            //   dc0d????????         |                     
            //   dd1c24               | fstp                qword ptr [esp]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8d850cf1ffff         | lea                 eax, dword ptr [ebp - 0xef4]
            //   68????????           |                     
            //   50                   | push                eax

    condition:
        7 of them and filesize < 106496
}