import "math"

rule win_plugx_encrypted_hunting {
   meta:
      description = "Detects encrypted PlugX payloads"
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-10-29"
      hash1 = "6b8081606762a2a9b88e356c9e3669771ac8bb6aaf905050b9ecd0b490aa2466"
      hash2 = "8ec409c1537e3030405bc8f8353d2605d1e88f1b245554383682f3aa8b5100ec"
      hash3 = "acfd58369c0a7dbc866ad4ca9cb0fe69d017587af88297f1eaf62a9a8b1b74b4"
      hash4 = "27ea939f41712a8655dc2dc0bce7d32a85e73a341e52b811b109befc043e762a"
      hash5 = "8889d2b18fb368fbfc16f622fcc20df1b9e522c2bada0195f9a812867f6bad91"
      hash6 = "d8882948a7fe4b16fb4b7c16427fbdcf0f0ab8ff3c4bac34f69b0a7d4718183e"
      further_reading = "https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.120.9861&rep=rep1&type=pdf"
   condition:

      math.in_range(math.mean(0, 16), 70.0, 110.0) // there is an ascii string at beginning (== xor key)
      and math.in_range(math.mean(filesize-8, 8), 70.0, 110.0) // the end of the file reflects the xor key since usually (000000...)
      and math.in_range(math.mean(0x300, 256), 70.0, 110.0) // before (unencrypted) .text section there are usually many zeros. These reflect the xor key in the encrypted version.
      and math.in_range(math.mean(0x30, 16), 70.0, 110.0) // since there are many zeros in the PE header, these bytes will have the value of the xor key in the encrypted version.

      and math.in_range(math.entropy(0, 8), 2.0, 4.0) // ensure that the file does not start with zero bytes and hopefully an ASCII key
      and math.in_range(math.entropy(0, 1000), 4.0, 6.0) // check if key repeats due to zero bytes in PE header
      and math.in_range(math.entropy(filesize - 32, 32), 2.0, 4.5) // check if key repeats due to zero bytes at the file end

      and math.entropy(0x410, 176) > 5.0 // entropy of encrypted .TEXT section should be still above 5.0 (see further_reading)
      and math.mean(0x3d0, 48) > 10 // assume that before text section there are no zero bytes in the encrypted version

      and filesize > 70KB
      and filesize < 250KB // check if size is in range for plugx

      and ((math.mean(8, 1) == 0)
           or (math.mean(9, 1) == 0)
           or (math.mean(10, 1) == 0)
           or (math.mean(11, 1) == 0)
           or (math.mean(12, 1) == 0)
           or (math.mean(13, 1) == 0)
           or (math.mean(14, 1) == 0)
           or (math.mean(15, 1) == 0)) // ensure there is a zero terminator of the key somewhere at the beginning, allow key length 9 - 16 bytes.
}
