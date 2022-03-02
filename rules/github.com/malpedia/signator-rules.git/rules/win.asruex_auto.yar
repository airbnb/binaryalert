rule win_asruex_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.asruex."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asruex"
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
        $sequence_0 = { 3c78 7404 3c58 7505 }
            // n = 4, score = 300
            //   3c78                 | cmp                 al, 0x78
            //   7404                 | je                  6
            //   3c58                 | cmp                 al, 0x58
            //   7505                 | jne                 7

        $sequence_1 = { 740c 3c09 7408 3c0d 7404 3c0a 7516 }
            // n = 7, score = 300
            //   740c                 | je                  0xe
            //   3c09                 | cmp                 al, 9
            //   7408                 | je                  0xa
            //   3c0d                 | cmp                 al, 0xd
            //   7404                 | je                  6
            //   3c0a                 | cmp                 al, 0xa
            //   7516                 | jne                 0x18

        $sequence_2 = { 7404 3c58 7505 bb01000000 }
            // n = 4, score = 300
            //   7404                 | je                  6
            //   3c58                 | cmp                 al, 0x58
            //   7505                 | jne                 7
            //   bb01000000           | mov                 ebx, 1

        $sequence_3 = { 85c0 740e 85ed 740a }
            // n = 4, score = 300
            //   85c0                 | test                eax, eax
            //   740e                 | je                  0x10
            //   85ed                 | test                ebp, ebp
            //   740a                 | je                  0xc

        $sequence_4 = { 83f801 740e 83f803 7409 83f802 }
            // n = 5, score = 300
            //   83f801               | cmp                 eax, 1
            //   740e                 | je                  0x10
            //   83f803               | cmp                 eax, 3
            //   7409                 | je                  0xb
            //   83f802               | cmp                 eax, 2

        $sequence_5 = { e8???????? 83f8ff 7407 3d0000a000 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   7407                 | je                  9
            //   3d0000a000           | cmp                 eax, 0xa00000

        $sequence_6 = { 3c78 7404 3c58 7505 bb01000000 }
            // n = 5, score = 300
            //   3c78                 | cmp                 al, 0x78
            //   7404                 | je                  6
            //   3c58                 | cmp                 al, 0x58
            //   7505                 | jne                 7
            //   bb01000000           | mov                 ebx, 1

        $sequence_7 = { 7408 3c0d 7404 3c0a 7516 }
            // n = 5, score = 300
            //   7408                 | je                  0xa
            //   3c0d                 | cmp                 al, 0xd
            //   7404                 | je                  6
            //   3c0a                 | cmp                 al, 0xa
            //   7516                 | jne                 0x18

        $sequence_8 = { 3c09 7408 3c0d 7404 3c0a 7516 }
            // n = 6, score = 300
            //   3c09                 | cmp                 al, 9
            //   7408                 | je                  0xa
            //   3c0d                 | cmp                 al, 0xd
            //   7404                 | je                  6
            //   3c0a                 | cmp                 al, 0xa
            //   7516                 | jne                 0x18

        $sequence_9 = { 3c0d 7404 3c0a 7516 }
            // n = 4, score = 300
            //   3c0d                 | cmp                 al, 0xd
            //   7404                 | je                  6
            //   3c0a                 | cmp                 al, 0xa
            //   7516                 | jne                 0x18

    condition:
        7 of them and filesize < 1564672
}