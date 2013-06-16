#include <stdint.h>
#include <cuda_runtime.h>

void *libgpu_device_mem_alloc(unsigned long size)
{
	void *mem;
	cudaMalloc(&mem, size);
	return mem;
}


void libgpu_device_mem_free(uint8_t *mem)
{
	if (mem) {
		cudaFree(mem);
		mem = NULL;
	}
}

void *libgpu_pinned_mem_alloc(unsigned long size)
{
	void *mem;
	cudaHostAlloc(&mem, size, cudaHostAllocWriteCombined);
	return mem;
}

void libgpu_pinned_mem_free(uint8_t *mem)
{
	if (mem) {
		cudaFreeHost(mem);
		mem = NULL;
	}
}

void libgpu_transfer_to_device(void *to, void *from, int size, cudaStream_t stream_id)
{
	cudaMemcpyAsync(to, from, size, cudaMemcpyHostToDevice, stream_id);
}

void libgpu_transfer_to_host(void *to, void *from, int size, cudaStream_t stream_id)
{
	cudaMemcpyAsync(to, from, size, cudaMemcpyDeviceToHost, stream_id);
}

void libgpu_sync()
{
	cudaDeviceSynchronize();
}
