CLANG = clang

EXECABLE = xdp_port
BASIC_SOCKET = sockb
USR_BUF_RS = usr_buf_rs

BPFCODE = xdp_port

BPFTOOLS = $(KERNELDIR)/samples/bpf
#BPFLOADER = $(BPFTOOLS)/bpf_load.c

CCINCLUDE += -I$(KERNELDIR)/tools/testing/selftests/bpf

LOADINCLUDE += -I$(KERNELDIR)/include
LOADINCLUDE += -I$(KERNELDIR)/arch/x86/include
LOADINCLUDE += -I$(KERNELDIR)/samples/bpf
LOADINCLUDE += -I$(KERNELDIR)/tools/lib
LOADINCLUDE += -I$(KERNELDIR)/tools/perf
LOADINCLUDE += -I$(KERNELDIR)/tools/include
LIBRARY_PATH = -L/usr/local/lib64
BPFSO = -lbpf -lelf

#.PHONY: clean $(CLANG) bpfload build ubfrs
.PHONY: clean $(CLANG)  build ubfrs

clean:
	rm -f *.o *.so $(EXECABLE) $(BASIC_SOCKET) $(USR_BUF_RS)

#build: ${BPFCODE.c} ${BPFLOADER}
build:
	$(CLANG) -O2 -target bpf  -o ${BPFCODE:=.o} $(LOADINCLUDE)  $(CCINCLUDE) -c $(BPFCODE:=.c)

#bpfload: build
#	$(CLANG) -o $(EXECABLE) $(LOADINCLUDE) $(LIBRARY_PATH) $(BPFSO) \
#        $(BPFLOADER) loader.c

ubfrs:
	$(CLANG) -o $(USR_BUF_RS) poll_usr_buf_rawsocket.c

$(EXECABLE): build


$(BASIC_SOCKET): ubfrs
	$(CLANG) -o $(BASIC_SOCKET) socket_basics.c

.DEFAULT_GOAL := $(BASIC_SOCKET)
