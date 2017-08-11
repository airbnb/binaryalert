rule ransomware_windows_cryptolocker
{
    meta:
        description = "The CryptoLocker malware propagated via infected email attachments, and via an existing botnet; when activated, the malware encrypts files stored on local and mounted network drives"
        reference = "https://www.secureworks.com/research/cryptolocker-ransomware"
        author = "@fusionrace"
        md5 = "012d9088558072bc3103ab5da39ddd54"
    strings:
        $u0 = "Paysafecard is an electronic payment method for predominantly online shopping" fullword ascii wide
        $u1 = "bb to select the method of payment and the currency." fullword ascii wide
        $u2 = "Where can I purchase a MoneyPak?" fullword ascii wide
        $u3 = "Ukash is electronic cash and e-commerce brand." fullword ascii wide
        $u4 = "You have to send below specified amount to Bitcoin address" fullword ascii wide
        $u5 = "cashU is a prepaid online" fullword ascii wide
        $u6 = "Your important files \\b encryption" fullword ascii wide
        $u7 = "Encryption was produced using a \\b unique\\b0  public key" fullword ascii wide
        $u8 = "then be used to pay online, or loaded on to a prepaid card or eWallet." fullword ascii wide
        $u9 = "Arabic online gamers and e-commerce buyers." fullword ascii wide
    condition:
        2 of them
}
