rule loocipher_ransomware {

   meta:

      description = "Rule to detect Loocipher ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-12-05"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Loocipher"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/analysis-of-loocipher-a-new-ransomware-family-observed-this-year/"
      hash = "7720aa6eb206e589493e440fec8690ceef9e70b5e6712a9fec9208c03cac7ff0"
      
   strings:

      $x1 = "c:\\users\\usuario\\desktop\\cryptolib\\gfpcrypt.h" fullword ascii
      $x2 = "c:\\users\\usuario\\desktop\\cryptolib\\eccrypto.h" fullword ascii
      $s3 = "c:\\users\\usuario\\desktop\\cryptolib\\gf2n.h" fullword ascii
      $s4 = "c:\\users\\usuario\\desktop\\cryptolib\\queue.h" fullword ascii
      $s5 = "ThreadUserTimer: GetThreadTimes failed with error " fullword ascii
      $s6 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::operator *" fullword wide
      $s7 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::operator +=" fullword wide
      $s8 = "std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class std::allocator<unsigned short> >::operator []" fullword wide
      $s9 = "std::vector<struct CryptoPP::ProjectivePoint,class std::allocator<struct CryptoPP::ProjectivePoint> >::operator []" fullword wide
      $s10 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::operator *" fullword wide
      $s11 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::operator +=" fullword wide
      $s12 = "std::vector<struct CryptoPP::WindowSlider,class std::allocator<struct CryptoPP::WindowSlider> >::operator []" fullword wide
      $s13 = "std::istreambuf_iterator<char,struct std::char_traits<char> >::operator ++" fullword wide
      $s14 = "std::istreambuf_iterator<char,struct std::char_traits<char> >::operator *" fullword wide
      $s15 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::_Compat" fullword wide
      $s16 = "std::vector<class CryptoPP::PolynomialMod2,class std::allocator<class CryptoPP::PolynomialMod2> >::operator []" fullword wide
      $s17 = "DL_ElgamalLikeSignatureAlgorithm: this signature scheme does not support message recovery" fullword ascii
      $s18 = "std::vector<struct CryptoPP::ECPPoint,class std::allocator<struct CryptoPP::ECPPoint> >::operator []" fullword wide
      $s19 = "std::vector<struct CryptoPP::EC2NPoint,class std::allocator<struct CryptoPP::EC2NPoint> >::operator []" fullword wide
      $s20 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::_Compat" fullword wide

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 17000KB and
      ( 1 of ($x*) and
      4 of them ) ) or
      ( all of them )
}
