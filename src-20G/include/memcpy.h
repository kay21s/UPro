#ifndef MEMCPY_H
#define MEMCPY_H

void *memcpy_sse2(void * to, const void * from, size_t len);
void *memcpy_c(void *dest, const void *src, size_t count); 

#endif
