rule Shellcode_APIHashing_FIN8 {
	meta:
		description = "Detects FIN8 Shellcode APIHashing"
		author = "Frank Boldewin (@r3c0nst)"
		date = "2021-03-16"
		reference = "https://www.bitdefender.com/files/News/CaseStudies/study/394/Bitdefender-PR-Whitepaper-BADHATCH-creat5237-en-EN.pdf"

	strings:
		$APIHashing32bit1 = {68 F2 55 03 88 68 65 19 6D 1E} 
		$APIHashing32bit2 = {68 9B 59 27 21 C1 E9 17 33 4C 24 10 68 37 5C 32 F4} 
		
		$APIHashing64bit = {49 BF 65 19 6D 1E F2 55 03 88 49 BE 37 5C 32 F4 9B 59 27 21} 
		
	condition:
		all of ($APIHashing32bit*) or $APIHashing64bit

     /*
	#include <string.h>
	#include <stdio.h>
	#include <stdint.h>
	#include <inttypes.h>
	
	static uint64_t hash_fast64(const void *buf, size_t len, uint64_t seed)
	{
		const uint64_t    m = 0x880355f21e6d1965ULL;
		const uint64_t *pos = (const uint64_t *)buf;
		const uint64_t *end = pos + (len >> 3);
		const unsigned char *pc;
		uint64_t h = len * m ^ seed;
		uint64_t v;
		
		while (pos != end)
		{
			v = *pos++;
			v ^= v >> 23;
			v *= 0x2127599bf4325c37ULL;
			h ^= v ^ (v >> 47);
			h *= m;
		}
		
		pc = (const unsigned char*)pos;
		v = 0;
		
		switch (len & 7) {
			case 7: v ^= (uint64_t)pc[6] << 48;
			case 6: v ^= (uint64_t)pc[5] << 40;
			case 5: v ^= (uint64_t)pc[4] << 32;
			case 4: v ^= (uint64_t)pc[3] << 24;
			case 3: v ^= (uint64_t)pc[2] << 16;
			case 2: v ^= (uint64_t)pc[1] << 8;
			case 1: v ^= (uint64_t)pc[0];
			v ^= v >> 23;
			v *= 0x2127599bf4325c37ULL;
			h ^= v ^ (v >> 47);
			h *= m;
		}

		h ^= h >> 23;
		h *= 0x2127599bf4325c37ULL;
		h ^= h >> 47;
		return h;
	}

	void main (void)
	{
		uint64_t h = 0;
		uint64_t seed = 0x0AB00D73069525D99; // Searching for precalculated hashes is quite useless, as new seeds change results.
		char buf[12] = "VirtualAlloc"; // Sample API Function
	
		h = hash_fast64(buf, 12, seed);
		printf ("Hash: 0x%16llx\n",h);   // Output as expected "Hash: 0xb6233cd91b71af58"
	}
     */
}
