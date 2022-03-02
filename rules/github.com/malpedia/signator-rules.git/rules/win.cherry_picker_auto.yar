rule win_cherry_picker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.cherry_picker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cherry_picker"
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
        $sequence_0 = { 83c408 2bf2 8a11 88140e 41 84d2 }
            // n = 6, score = 300
            //   83c408               | add                 esp, 8
            //   2bf2                 | sub                 esi, edx
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   88140e               | mov                 byte ptr [esi + ecx], dl
            //   41                   | inc                 ecx
            //   84d2                 | test                dl, dl

        $sequence_1 = { 6a3c 68???????? 68???????? a3???????? ffd6 69c0e8030000 68???????? }
            // n = 7, score = 300
            //   6a3c                 | push                0x3c
            //   68????????           |                     
            //   68????????           |                     
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   69c0e8030000         | imul                eax, eax, 0x3e8
            //   68????????           |                     

        $sequence_2 = { 85c0 7512 68???????? 50 50 ff15???????? a3???????? }
            // n = 7, score = 300
            //   85c0                 | test                eax, eax
            //   7512                 | jne                 0x14
            //   68????????           |                     
            //   50                   | push                eax
            //   50                   | push                eax
            //   ff15????????         |                     
            //   a3????????           |                     

        $sequence_3 = { 6a00 6a00 6a04 6a00 6a00 6800000040 68???????? }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6800000040           | push                0x40000000
            //   68????????           |                     

        $sequence_4 = { ffd3 68???????? 56 89442420 }
            // n = 4, score = 300
            //   ffd3                 | call                ebx
            //   68????????           |                     
            //   56                   | push                esi
            //   89442420             | mov                 dword ptr [esp + 0x20], eax

        $sequence_5 = { 8bf0 0fbec9 81e6ff000000 33f1 8a4a01 42 }
            // n = 6, score = 300
            //   8bf0                 | mov                 esi, eax
            //   0fbec9               | movsx               ecx, cl
            //   81e6ff000000         | and                 esi, 0xff
            //   33f1                 | xor                 esi, ecx
            //   8a4a01               | mov                 cl, byte ptr [edx + 1]
            //   42                   | inc                 edx

        $sequence_6 = { 68???????? 68e8030000 68???????? 68???????? a3???????? }
            // n = 5, score = 300
            //   68????????           |                     
            //   68e8030000           | push                0x3e8
            //   68????????           |                     
            //   68????????           |                     
            //   a3????????           |                     

        $sequence_7 = { 52 e8???????? 83c42c 6a00 6a00 6a04 6a00 }
            // n = 7, score = 300
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c42c               | add                 esp, 0x2c
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   6a00                 | push                0

        $sequence_8 = { 893d???????? e8???????? a1???????? 50 ff15???????? }
            // n = 5, score = 300
            //   893d????????         |                     
            //   e8????????           |                     
            //   a1????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_9 = { 6a3c 68???????? 68???????? a3???????? }
            // n = 4, score = 300
            //   6a3c                 | push                0x3c
            //   68????????           |                     
            //   68????????           |                     
            //   a3????????           |                     

    condition:
        7 of them and filesize < 712704
}