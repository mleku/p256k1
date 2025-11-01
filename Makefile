# Simple Makefile for p256k1 library
# For BIP-340 X-only public keys, signatures, and ECDH

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
DEFINES = -DSECP256K1_BUILD=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_ECDH=1
INCLUDES = -Iinclude -Isrc

# Source files
SOURCES = src/secp256k1.c src/precomputed_ecmult.c src/precomputed_ecmult_gen.c
OBJECTS = $(SOURCES:.c=.o)

# Library name
LIBRARY = libp256k1.a
SHARED_LIB = libp256k1.so

# Default target
all: $(LIBRARY) $(SHARED_LIB) examples

# Static library
$(LIBRARY): $(OBJECTS)
	ar rcs $@ $^

# Shared library
$(SHARED_LIB): $(OBJECTS)
	$(CC) -shared -o $@ $^

# Object files
%.o: %.c
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -fPIC -c $< -o $@

# Examples
examples: examples/schnorr examples/ecdh

examples/schnorr: examples/schnorr.c $(LIBRARY)
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $< -L. -lp256k1

examples/ecdh: examples/ecdh.c $(LIBRARY)
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $< -L. -lp256k1

# Clean
clean:
	rm -f $(OBJECTS) $(LIBRARY) $(SHARED_LIB) examples/schnorr examples/ecdh

# Install (basic)
install: $(LIBRARY) $(SHARED_LIB)
	mkdir -p /usr/local/lib /usr/local/include
	cp $(LIBRARY) $(SHARED_LIB) /usr/local/lib/
	cp include/*.h /usr/local/include/

.PHONY: all clean install examples
