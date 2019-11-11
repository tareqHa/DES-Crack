#pragma once
#include "Header.cuh"

void pause_console()
{
	int xx;
	scanf("%d", &xx);
}

// generate a random key
void generate_key(uint64_t* main_key)
{
	srand(time(NULL));
	for (int i = 0; i < 64; ++i) {
		if (rand() % 2 == 1) {
			*main_key |= (1LL << i);
		}
	}
}

// read a message of characters into 64 bit long long interger
void padding(uint64_t* message, char* plaintext)
{
	int l = strlen(plaintext);
#ifdef HEX
	for (int i = 0; i < 16; ++i) {
		message[0] <<= 4;
		message[0] |= hex_to_int(plaintext[i]);
	}
#else
	for (int j = 0; j < 8; j++) {
		*message <<= 8; // shift 8 bits for new character
		if (j < l)
			*message |= (uint64_t)plaintext[j];
	}
#endif
}

__device__ __host__ void print(uint64_t par)
{
	puts("");
	for (int i = 63; i >= 0; i--) {
		printf("%d", ISON(par, i));
		if ((63 - i + 1) % 6 == 0)	// print every 6 bits
			printf(" ");
	}
	puts("");
}
void print(char* par, int k)
{
	puts("");
	for (int i = k - 1; i >= 0; --i) {
		printf("%c", par[i]);
	}
	puts("");
}


void int_to_string(uint64_t in, char* par)
{
	for (int i = 0; i < 16; i++) {
		uint64_t now = 0;
		for (int j = 0; j < 4; j++) {
			if (ISON(in, i * 4 + j))
				now = MAKEON(now, j);
		}
		if (now < 10) {
			par[i] = (char)(now + '0');
		}
		else {
			par[i] = (char)(now - 10 + 'A');
		}
	}
	par[16] = '\0';
}
void print_in_hex(uint64_t par)
{
	char all[17];
	int_to_string(par, all);
	print(all, 16);
}

uint64_t string_to_int(char* in)
{
	uint64_t ret = 0;
	for (int i = 0; i < 16; ++i) {
		ret <<= 4;
		if (isdigit(in[i])) {
			ret |= (uint64_t)(in[i] - '0');
		}
		else {
			ret |= (uint64_t)(in[i] - 'A' + 10);
		}
	}
	return ret;
}

int hex_to_int(char par)
{
	if (isdigit(par)) {
		return par - '0';
	}
	return par - 'A' + 10;
}

char int_to_hex(int par)
{
	if (par < 10) {
		return '0' + par;
	}
	return 'A' + par - 10;
}

// print a message
void show_message(uint64_t encrypted_message)
{
	char par[17];
	puts("");
	int_to_string(encrypted_message, par);
	for (int j = 15; j >= 0; --j) {
		printf("%c", par[j]);
	}
	puts("");
}


// get part of the main key
uint64_t get_partial_key(uint64_t key, int bits)
{
	uint64_t ret = 0;
	for (int i = 63; i >= 0; --i) {
		if (bits > 0 || (i + 1) % 8 == 0) {
			ret = ISON(key, i) ? MAKEON(ret, i) : MAKEOFF(ret, i);
			bits--;
		}
	}
	return ret;
}



