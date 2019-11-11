// this file implements the algorithm specified in here http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm


#pragma once
#include "Header.cuh"
#include "des_consts.h"
#include "utils.cuh"

char plaintext[100000] = "hello wo";

uint64_t main_key;


__device__  void encode_message(uint64_t* subkeys, uint64_t* encrypted_message, uint64_t message);
__device__  void generate_subkeys(uint64_t key, uint64_t* subkeys);


__device__  void run_des(uint64_t key, uint64_t message, uint64_t* encrypted_message)
{
	uint64_t subkeys[17] = { 0 };
	generate_subkeys(key, subkeys);
	encode_message(subkeys, encrypted_message, message);
}

// shift bits to the left
__device__  __host__ uint64_t shift_left(uint64_t in, int times)
{
	uint64_t ret = 0;
	while (times--) {
		for (int i = 0; i < 28; ++i) {
			if (i == 0) {
				ret = ISON(in, 27) ? MAKEON(ret, i) : MAKEOFF(ret, i);
			}
			else {
				ret = ISON(in, i - 1) ? MAKEON(ret, i) : MAKEOFF(ret, i);

			}
		}
		in = ret;
	}

	return ret;
}

// concatenate two 28 bit numbers into one 56 bit number
__device__  __host__ uint64_t concatenate(uint64_t a, uint64_t b)
{
	uint64_t ret = 0;
	for (int i = 0; i < 28; ++i) {
		ret = ISON(a, i) ? MAKEON(ret, i + 28) : MAKEOFF(ret, i + 28);
		ret = ISON(b, i) ? MAKEON(ret, i) : MAKEOFF(ret, i);
	}
	return ret;
}



__device__ void generate_subkeys(uint64_t key, uint64_t* subkeys)
{
	int* PC_1;
	int* SHIFTS;
	int* PC_2;

	PC_1 = dev_PC_1;
	SHIFTS = dev_SHIFTS;
	PC_2 = dev_PC_2;

	uint64_t to56 = 0;
	for (int i = 0; i < 56; ++i) {
		to56 = ISON(key, 64 - PC_1[i]) ? MAKEON(to56, 55 - i) : MAKEOFF(to56, 55 - i);
	}
	uint64_t c[17] = { 0 };
	uint64_t d[17] = { 0 };
	for (int i = 0; i < 28; ++i) {
		if (ISON(to56, i))
			d[0] |= (1LL << i);
		if (ISON(to56, i + 28))
			c[0] |= (1LL << i);
	}

	for (int i = 1; i <= 16; ++i) {
		c[i] = shift_left(c[i - 1], SHIFTS[i - 1]);
		d[i] = shift_left(d[i - 1], SHIFTS[i - 1]);
	}


	for (int i = 1; i <= 16; ++i) {
		uint64_t tmp = concatenate(c[i], d[i]);
		for (int j = 0; j < 48; ++j) {
			subkeys[i - 1] = ISON(tmp, 56 - PC_2[j]) ? MAKEON(subkeys[i - 1], 47 - j) : MAKEOFF(subkeys[i - 1], 47 - j);
		}
	}
}



__device__  uint64_t E(uint64_t r)
{
	int* E_BIT;
	E_BIT = dev_E_BIT;

	uint64_t ret = 0;
	for (int i = 0; i < 48; ++i) {
		if (ISON(r, 32 - E_BIT[i]))
			ret = MAKEON(ret, 47 - i);
	}
	return ret;
}
__device__  uint64_t f(uint64_t r, uint64_t k)
{
	int** S;
	int* P;
	S = dev_S;
	P = dev_P;

	uint64_t now = 0, ret = 0;
	uint64_t Er = E(r);
	now = Er ^ k;
	uint64_t S_now[8] = { 0 };
	for (int i = 0; i < 8; i++) {
		uint64_t a = 0, b = 0;
		if (ISON(now, 0))	// first bit
			a = MAKEON(a, 0);
		if (ISON(now, 5))	// last bit
			a = MAKEON(a, 1);

		if (ISON(now, 1))
			b = MAKEON(b, 0);
		if (ISON(now, 2))
			b = MAKEON(b, 1);
		if (ISON(now, 3))
			b = MAKEON(b, 2);
		if (ISON(now, 4))
			b = MAKEON(b, 3);

		int idx = a * 16 + b;

		S_now[7 - i] = S[7 - i][idx];
		now >>= 6;	// 6 bits
	}

	ret = S_now[0] << 28 |
		S_now[1] << 24 |
		S_now[2] << 20 |
		S_now[3] << 16 |
		S_now[4] << 12 |
		S_now[5] << 8 |
		S_now[6] << 4 |
		S_now[7] << 0;

	now = ret;
	for (int i = 0; i < 32; ++i) {
		ret = ISON(now, 32 - P[i]) ? MAKEON(ret, 31 - i) : MAKEOFF(ret, 31 - i);
	}
	return ret;
}
__device__  void encode_message(uint64_t* subkeys, uint64_t* encrypted_message, uint64_t message)
{
	int* IP;
	int* IP_REV;
	IP = dev_IP;
	IP_REV = dev_IP_REV;

	uint64_t tmp = message;
	for (int i = 0; i < 64; ++i) {
		message = ISON(tmp, 64 - IP[i]) ? MAKEON(message, 63 - i) : MAKEOFF(message, 63 - i);
	}
	uint64_t now = message;
	uint64_t l[17] = { 0 };
	uint64_t r[17] = { 0 };
	for (int i = 0; i < 32; ++i) {
		if (ISON(now, i))
			r[0] = MAKEON(r[0], i);
		if (ISON(now, i + 32))
			l[0] = MAKEON(l[0], i);
	}
	for (int i = 1; i <= 16; ++i) {
		l[i] = r[i - 1];
		r[i] = l[i - 1] ^ f(r[i - 1], subkeys[i - 1]);
	}
	uint64_t reverse = r[16];
	reverse <<= 32;
	reverse |= l[16];
	now = reverse;
	for (int i = 0; i < 64; ++i) {
		reverse = ISON(now, 64 - IP_REV[i]) ? MAKEON(reverse, 63 - i) : MAKEOFF(reverse, 63 - i);
	}
	*encrypted_message = reverse;
}


//----------------------------------HOST---------------------------------------------------------------------------------------------------------------------


__host__ void h_generate_subkeys(uint64_t key, uint64_t* subkeys);
__host__ void h_encode_message(uint64_t* subkeys, uint64_t* encrypted_message, uint64_t message);

__host__ void h_run_des(uint64_t key, uint64_t message, uint64_t* encrypted_message)
{
	uint64_t subkeys[17] = { 0 };
	h_generate_subkeys(key, subkeys);

	h_encode_message(subkeys, encrypted_message, message);
}

__host__ void h_generate_subkeys(uint64_t key, uint64_t* subkeys)
{
	int* PC_1;
	int* SHIFTS;
	int* PC_2;
	PC_1 = h_PC_1;
	SHIFTS = h_SHIFTS;
	PC_2 = h_PC_2;

	uint64_t to56 = 0;
	for (int i = 0; i < 56; ++i) {
		to56 = ISON(key, 64 - PC_1[i]) ? MAKEON(to56, 55 - i) : MAKEOFF(to56, 55 - i);
	}
	uint64_t c[17] = { 0 };
	uint64_t d[17] = { 0 };
	for (int i = 0; i < 28; ++i) {
		if (ISON(to56, i))
			d[0] |= (1LL << i);
		if (ISON(to56, i + 28))
			c[0] |= (1LL << i);
	}
	for (int i = 1; i <= 16; ++i) {
		c[i] = shift_left(c[i - 1], SHIFTS[i - 1]);
		d[i] = shift_left(d[i - 1], SHIFTS[i - 1]);
	}

	for (int i = 1; i <= 16; ++i) {
		uint64_t tmp = concatenate(c[i], d[i]);
		for (int j = 0; j < 48; ++j) {
			subkeys[i - 1] = ISON(tmp, 56 - PC_2[j]) ? MAKEON(subkeys[i - 1], 47 - j) : MAKEOFF(subkeys[i - 1], 47 - j);
		}
	}
}

__host__ uint64_t h_E(uint64_t r)
{
	int* E_BIT;
	E_BIT = h_E_BIT;


	uint64_t ret = 0;
	for (int i = 0; i < 48; ++i) {
		if (ISON(r, 32 - h_E_BIT[i]))
			ret = MAKEON(ret, 47 - i);
	}
	return ret;
}
__host__ uint64_t h_f(uint64_t r, uint64_t k)
{
	int** S;
	int* P;

	S = h_S;
	P = h_P;


	uint64_t now = 0, ret = 0;
	uint64_t Er = h_E(r);
	now = Er ^ k;
	uint64_t S_now[8] = { 0 };
	for (int i = 0; i < 8; i++) {
		uint64_t a = 0, b = 0;
		if (ISON(now, 0))	// first bit
			a = MAKEON(a, 0);
		if (ISON(now, 5))	// last bit
			a = MAKEON(a, 1);

		if (ISON(now, 1))
			b = MAKEON(b, 0);
		if (ISON(now, 2))
			b = MAKEON(b, 1);
		if (ISON(now, 3))
			b = MAKEON(b, 2);
		if (ISON(now, 4))
			b = MAKEON(b, 3);

		int idx = a * 16 + b;

		S_now[7 - i] = S[7 - i][idx];
		now >>= 6;	// 6 bits
	}
	for (int i = 0; i < 8; ++i) {
		ret <<= 4;
		ret |= S_now[i];
	}
	now = ret;
	for (int i = 0; i < 32; ++i) {
		ret = ISON(now, 32 - P[i]) ? MAKEON(ret, 31 - i) : MAKEOFF(ret, 31 - i);
	}
	return ret;
}
__host__ void h_encode_message(uint64_t* subkeys, uint64_t* encrypted_message, uint64_t message)
{
	int* IP;
	int* IP_REV;

	IP = h_IP;
	IP_REV = h_IP_REV;


	uint64_t tmp = message;
	for (int i = 0; i < 64; ++i) {
		message = ISON(tmp, 64 - IP[i]) ? MAKEON(message, 63 - i) : MAKEOFF(message, 63 - i);
	}
	uint64_t now = message;
	uint64_t l[17] = { 0 };
	uint64_t r[17] = { 0 };
	for (int i = 0; i < 32; ++i) {
		if (ISON(now, i))
			r[0] = MAKEON(r[0], i);
		if (ISON(now, i + 32))
			l[0] = MAKEON(l[0], i);
	}
	for (int i = 1; i <= 16; ++i) {
		l[i] = r[i - 1];
		r[i] = l[i - 1] ^ h_f(r[i - 1], subkeys[i - 1]);
	}
	uint64_t reverse = r[16];
	reverse <<= 32;
	reverse |= l[16];
	now = reverse;
	for (int i = 0; i < 64; ++i) {
		reverse = ISON(now, 64 - IP_REV[i]) ? MAKEON(reverse, 63 - i) : MAKEOFF(reverse, 63 - i);
	}
	*encrypted_message = reverse;
}