#pragma once
#include "run_des.cuh"
#include "Header.cuh"


int bits = 15;	// half		// 37 took 1 min




__global__ void crack_des(uint64_t* final_key, int limit, uint64_t message, uint64_t encoded, bool* done, int k)
{
	if (*done == 1)
		return;
	uint64_t mid = 1ULL * threadIdx.x + (blockIdx.x) * blockDim.x + k * 1ULL * limit;
	uint64_t encrypted_message;
	uint64_t now = mid | (*final_key);
	run_des(now, message, &encrypted_message);
	
	// compare the new encoded message with the original one
	if (encoded == encrypted_message) {
		*final_key = now;
		*done = 1;
	}
}




cudaError_t kernel(uint64_t* final_key, uint64_t message, uint64_t encoded)
{
	cudaError_t cudaStatus;

	// Choose which GPU to run on, change this on a multi-GPU system.
	cudaStatus = cudaSetDevice(0);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaSetDevice failed!  Do you have a CUDA-capable GPU installed?");
	}

	uint64_t* dev_final_key;
	bool* dev_done;

	dim3 block(4096 * 1, 1, 1);	// 40 bit
	dim3 thread(512, 1, 1);
	uint64_t nom = ((1ULL << (bits)));
	uint64_t dom = (1ULL * block.x * thread.x);
	int limit = nom / dom + 1;
	bool done = 0;

	cudaStatus = cudaMalloc((void**)&dev_done, sizeof(bool));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
	}



	cudaStatus = cudaMalloc((void**)&dev_final_key, sizeof(uint64_t));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
	}


	cudaStatus = cudaMemcpy(dev_done, &done, sizeof(bool), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy failed! ");
	}

	cudaStatus = cudaMemcpy(dev_final_key, final_key, sizeof(uint64_t), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy failed! ");
	}



	cudaEvent_t start, end; float time;
	cudaEventCreate(&start);
	cudaEventCreate(&end);

	cudaEventRecord(start, 0);
	printf("\Loops = %d\n", limit);
	for (int i = 0; i < limit; ++i) {
		crack_des <<< block, thread >>> (dev_final_key, block.x * thread.x, message, encoded, dev_done, i);
	}

	cudaDeviceSynchronize();
	cudaEventRecord(end, 0);
	cudaEventSynchronize(end);
	cudaEventElapsedTime(&time, start, end);
	cudaEventDestroy(start);
	cudaEventDestroy(end);
	printf("DEVICE FINISHED, time = %f ms\n", time);

	cudaStatus = cudaMemcpy(final_key, dev_final_key, sizeof(uint64_t), cudaMemcpyDeviceToHost);
	cudaStatus = cudaMemcpy(&done, dev_done, sizeof(bool), cudaMemcpyDeviceToHost);

	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy failed! %d", cudaStatus);
	}

	cudaFree(dev_final_key);
	if (done == 1) {
		printf("KEY IS FOUND\n");
	}
	return cudaStatus;
}


// brute force on CPU
void crack_des_host(uint64_t message, uint64_t final_key, uint64_t encoded)
{
	clock_t cpu_start, cpu_end;
	float cpu_time = 0;
	cpu_start = clock();
	bool found = 0;
	uint64_t want;
	uint64_t all = (1ULL << (bits));
	for (uint64_t test = 0; test < all; test++) {
		uint64_t now = test | final_key;
		uint64_t encrypted_message;
		h_run_des(now, message, &encrypted_message);
		if (encoded == encrypted_message) {
			found = 1;
			want = now;
		}
	}

	cpu_end = clock();
	cpu_time = 1000.0 *  (cpu_end - cpu_start) / (1.0 * CLOCKS_PER_SEC);
	if (found) {
		printf("CPU FOUND IT :\n");
		print_in_hex(want);

		uint64_t tt, yy;
		h_run_des(want, message, &tt);
		h_run_des(main_key, message, &yy);
		if (tt == yy)
			printf("\nHOST THEY ARE EQUAL\n");

	}
	printf("\nhost ended!, time = %f ms\n", cpu_time);

}
int main()
{

	generate_key(&main_key);
	//main_key = string_to_int("0E329232EA6D0D73");
	//main_key = string_to_int("FFFFFFFFFFFFFFFF");
	printf("Keys is: ");
	print_in_hex(main_key);

	uint64_t message;
	uint64_t encrypted_message;
	padding(&message, plaintext);

	h_run_des(main_key, message, &encrypted_message);
	uint64_t final_key = get_partial_key(main_key, 64 - bits);
	uint64_t final_key_host = final_key;
	

	cudaError_t cudaStatus = kernel(&final_key, message, encrypted_message);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "NOT SUCCEDD!");
	}


	// <test if the key is correct>
	uint64_t encrypted_test;
	h_run_des(final_key, message, &encrypted_test);
	if (encrypted_test == encrypted_message)
		printf("\nTHEY ARE EQUIVALENT\n");
	printf("KEY FOUND IS: ");
	print_in_hex(final_key);
	// </test if the key is correct>

	// run on cpu
	crack_des_host(message, final_key_host, encrypted_message);

	pause_console();

	return 0;
}


