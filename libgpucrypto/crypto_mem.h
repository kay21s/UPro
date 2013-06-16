#ifndef CUDA_MEM_H
#define CUDA_MEM_H

#include <stdint.h>

void *libgpu_device_mem_alloc(unsigned long size);
void libgpu_device_mem_free(uint8_t *mem);
void *libgpu_pinned_mem_alloc(unsigned long size);
void libgpu_pinned_mem_free(uint8_t *mem);

void libgpu_sync();
void libgpu_transfer_to_host(void *to, void *from, int size, int stream_id);
void libgpu_transfer_to_device(void *to, void *from, int size, int stream_id);
#endif
