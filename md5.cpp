#include <iostream>
#include <string>

static inline uint32_t FF(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &Mj, uint16_t &s, uint32_t &ti);
static inline uint32_t GG(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &Mj, uint16_t &s, uint32_t &ti);
static inline uint32_t HH(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &Mj, uint16_t &s, uint32_t &ti);
static inline uint32_t II(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &Mj, uint16_t &s, uint32_t &ti);
void groupLoop(uint8_t buff[64], uint32_t res[4]);
void hexToStr(uint8_t hex[], size_t len, bool bUpcase, std::string &str);

/* 
 * src: the pointer to source data
 * srclen: the source data length (in byte)
 * md5: MD5 string buff which this function outputs.
 * maxlen: the maximum length of MD5 string buff.
 * b32bit: if this parameter is false then this function will release 16-bits MD5 code, otherwise 32-bits MD5 code.
 * bUpcase: set the output string with up case or low case.
 */
void MD5(const uint8_t * src, const size_t srclen, char * md5, const size_t maxlen, const bool b32bit, const bool bUpcase);

#define F(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))
#define G(X, Y, Z) (((X) & (Z)) | ((Y) & (~Z)))
#define H(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define I(X, Y, Z) ((Y) ^ ((X) | (~Z)))

// 4 functions: FF(), GG(), HH(), II(), do this, in order to simpling calling
uint32_t(*func[4])(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &Mj, uint16_t &s, uint32_t &ti) = { FF, GG, HH, II };

// count of bit shift
uint16_t s[4][4] = {
	{ 7, 12, 17, 22 },
	{ 5, 9, 14, 20 },
	{ 4, 11, 16, 23 },
	{ 6, 10, 15, 21 }
};

// magic constants
uint32_t ti[4][16] = {
	{ 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 },
	{ 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a },
	{ 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 },
	{ 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 }
};

// subgroup index table
uint32_t mi[4][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12 },
	{ 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2 },
	{ 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9 }
};

// ROL function
static inline uint32_t rol(uint32_t bin, uint16_t shift_bits) {
	shift_bits %= 32;
	return ((bin << shift_bits) | (bin >> (32 - shift_bits)));
}

static inline uint32_t FF(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &Mj, uint16_t &s, uint32_t &ti) {
	return a = b + rol((a + F(b, c, d) + Mj + ti), s);
}

static inline uint32_t GG(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &Mj, uint16_t &s, uint32_t &ti) {
	return a = b + rol((a + G(b, c, d) + Mj + ti), s);
}

static inline uint32_t HH(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &Mj, uint16_t &s, uint32_t &ti) {
	return a = b + rol((a + H(b, c, d) + Mj + ti), s);
}

static inline uint32_t II(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &Mj, uint16_t &s, uint32_t &ti) {
	return a = b + rol((a + I(b, c, d) + Mj + ti), s);
}

// handle per group (512 bit, 64 byte)
void groupLoop(uint8_t buff[64], uint32_t res[4])
{
	uint32_t m[16], d[4];
	std::memcpy(m, buff, sizeof(m));	// group data, divide into 16 integer
	std::memcpy(d, res, sizeof(d));	// get result (previous rotation)

	for (size_t i = 0; i < 4; i++) {	// do 4 rotation
		for (size_t j = 0; j < 4; j++) {
			for (size_t k = 0; k < 4; k++) {
				d[(4 - k) % 4] = func[i](d[(4 - k) % 4], d[(5 - k) % 4], d[(6 - k) % 4], d[(7 - k) % 4], m[mi[i][j * 4 + k]], s[i][k], ti[i][j * 4 + k]);
			}
		}
	}
	// after rotation, add them into result
	res[0] += d[0];
	res[1] += d[1];
	res[2] += d[2];
	res[3] += d[3];
}

void hexToStr(uint8_t hex[], size_t len, bool bUpcase, std::string &str) {
	char uhc[] = "0123456789ABCDEF"; // up case hex character index array
	char lhc[] = "0123456789abcdef"; // low case hex character index array
	// combine into string
	for (size_t i = 0; i < len; i++) {
		str.push_back(bUpcase ? uhc[hex[i] / 0x10] : lhc[hex[i] / 0x10]);
		str.push_back(bUpcase ? uhc[hex[i] % 0x10] : lhc[hex[i] % 0x10]);
	}
}

void MD5(const uint8_t * src, const size_t srclen, char * md5, const size_t maxstrlen, const bool b32bit, const bool bUpcase) {
	std::string str((char *)src);
	size_t ori_byte_len(srclen);
	bool flag = false;	// if fill with 0, otherwise fill with 1
	size_t i(ori_byte_len);

	while (i % 64 != 56) {	// if bit size is not equal to N * 512 + 448, then fill up
		flag = (flag ? str.push_back(0x00), true : str.push_back(0x80), true);
		i += 1;
	}
	
	uint64_t ori_bit_len = ori_byte_len * 8;	// bit length = byte length * 8
	for (i = 0; i < 8; i++) {	// the last 64 bit filled with the original data length
		str.push_back(((char *)&ori_bit_len)[i]);
	}

	size_t loops = str.size() / 64;	// times of loop
	const uint32_t d[4] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };	// 4 magic constants
	uint32_t res[4];	// 128-bit (4 * 32 bit) result
	std::memcpy(res, d, sizeof(d));	// use 4 magic constant as begin number at first rotation
	uint8_t buff[64];	// 64 byte (512 bit) buffer per rotation
	for (i = 0; i < loops; i++) {	// big loop, 512 bit per rotation
		std::memcpy(&buff, ((uint8_t *)(str.c_str())) + i * sizeof(buff), sizeof(buff));
		groupLoop(buff, res);
	}

	std::string md5str;	// get the md5 string
	if (!b32bit) {
		// 16-bits MD5
		hexToStr((uint8_t *)(res + 1), sizeof(res) / 2, bUpcase, md5str);
		strcpy_s(md5, maxstrlen, md5str.c_str());
	} else {
		// 32-bits MD5
		hexToStr((uint8_t *)res, sizeof(res), bUpcase, md5str);
		strcpy_s(md5, maxstrlen, md5str.c_str());
	}
}
