CC = gcc

################################################################
# OS Name (Linux or Darwin)
OSUPPER = $(shell uname -s 2>/dev/null | tr [:lower:] [:upper:])
OSLOWER = $(shell uname -s 2>/dev/null | tr [:upper:] [:lower:])

# Flags to detect 32-bit or 64-bit OS platform
OS_SIZE = $(shell uname -m | sed -e "s/i.86/32/" -e "s/x86_64/64/")
OS_ARCH = $(shell uname -m | sed -e "s/i386/i686/")

# These flags will override any settings
ifeq ($(i386),1)
	OS_SIZE = 32
	OS_ARCH = i686
endif

ifeq ($(x86_64),1)
	OS_SIZE = 64
	OS_ARCH = x86_64
endif

# Flags to detect either a Linux system (linux) or Mac OSX (darwin)
DARWIN = $(strip $(findstring DARWIN, $(OSUPPER)))

# Location of the CUDA Toolkit binaries and libraries
CUDA_PATH       ?= /usr/local/cuda-5.0
CUDA_INC_PATH   ?= $(CUDA_PATH)/include
CUDA_BIN_PATH   ?= $(CUDA_PATH)/bin
CUDA_SDK_DIR = /home/$(USER)/NVIDIA_CUDA-5.0_Samples/

ifneq ($(DARWIN),)
  CUDA_LIB_PATH  ?= $(CUDA_PATH)/lib
else
  ifeq ($(OS_SIZE),32)
    CUDA_LIB_PATH  ?= $(CUDA_PATH)/lib
  else
    CUDA_LIB_PATH  ?= $(CUDA_PATH)/lib64
  endif
endif

# Common binaries
NVCC            ?= $(CUDA_BIN_PATH)/nvcc

# CUDA code generation flags
GENCODE_SM20    := -gencode arch=compute_20,code=sm_20
GENCODE_SM30    := -gencode arch=compute_30,code=sm_30 -gencode arch=compute_35,code=sm_35
GENCODE_FLAGS   := $(GENCODE_SM20) $(GENCODE_SM30)

# OS-specific build flags
ifneq ($(DARWIN),) 
      LDFLAGS   := -Xlinker -rpath $(CUDA_LIB_PATH) -L$(CUDA_LIB_PATH) -lcudart
      CCFLAGS   := -arch $(OS_ARCH) 
else
  ifeq ($(OS_SIZE),32)
      LDFLAGS   := -L$(CUDA_LIB_PATH) -lcudart
      CCFLAGS   := -m32
  else
      LDFLAGS   := -L$(CUDA_LIB_PATH) -lcudart
      CCFLAGS   := -m64
  endif
endif

# OS-architecture specific flags
ifeq ($(OS_SIZE),32)
      NVCCFLAGS := -m32
else
      NVCCFLAGS := -m64
endif

# Debug build flags
ifeq ($(dbg),1)
      CCFLAGS   += -g
      NVCCFLAGS += -g -G
      TARGET    := debug
else
      TARGET    := release
endif


# Common includes and paths for CUDA
NVCCINCLUDES      := -I$(CUDA_INC_PATH) -I. -I$(CUDA_SDK_DIR)common/inc/

################################################################

CFLAGS = -Wall -g -D__USE_GNU -D_GNU_SOURCE -DUPRO_MALLOC -DDEBUG_0 -DTRANSFER_SEPERATE
# AFFINITY_1: collector[0,1,2,3] forwarders[4,5,6,7]
# AFFINITY_2: collector[0,2,4,6] forwarders[1,3,5,7]
# AFFINITY_3: collector[1,3,5,7] forwarders[2,4,6,8]
# AFFINITY_4: collector[1,2,3,4,..] forwarders[5,6,7,8,..] gpu_worker[0]
CFLAGS += -DCPU_AFFINITY -DAFFINITY_4
CFLAGS += -DNOT_FORWARD_0 -DNOT_GPU_0 -DNOT_COLLECT_0 
CFLAGS += -DCOLLECTOR_PERFORMANCE_TEST_0
CFLAGS += -DUSE_LOCK_0 -DMEMCPY_C_0 -DMEMCPY_SSE_0

LIBS = -lrt -lpthread -L../IOEngine/lib -lpsio
LIBS += -L../libgpucrypto/lib -lgpucrypto 

HEADER_DIR = ./include 
IOENGINE_DIR = ../IOEngine/include
LIBCRYPTO_DIR = ../libgpucrypto
OBJECT_DIR = objs
TARGET_DIR = .

TARGET_FILE = upro 
TARGET = $(addprefix $(TARGET_DIR)/, $(TARGET_FILE))

SOURCE_FILES = $(wildcard *.c)
HEADER_FILES = $(wildcard *.h) $(wildcard *.h)
OBJECT_FILE = $(SOURCE_FILES:.c=.o)

OBJECT = $(addprefix $(OBJECT_DIR)/, $(OBJECT_FILE))

all: $(TARGET)

$(TARGET): $(OBJECT) | $(TARGET_DIR) $(OBJECT_DIR)
	$(CC) -pg $(OBJECT) -o $@ $(LIBS) $(LDFLAGS)

$(OBJECT_DIR):
	mkdir $(OBJECT_DIR)


$(OBJECT_DIR)/%.o : %.c
	$(CC) -pg $(CFLAGS) -I $(HEADER_DIR) -I $(IOENGINE_DIR) -I $(LIBCRYPTO_DIR) $(NVCCINCLUDES) -c $< -o $@
# -I $(CUDA_INC_PATH) -I $(LIBCRYPTO_DIR)

.PHONY : clean
clean:
	rm -rf $(TARGET) $(OBJECT)

doc: $(SOURCE_FILES) doxygen.config
	doxygen doxygen.config
