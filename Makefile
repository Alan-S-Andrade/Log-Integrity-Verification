CC=$(CROSS)gcc
CFLAGS=-O2 -Wall -DDEBUG
INCLUDES=-I siphash/ -I blake/
RM=rm -f

proof: proof_verification.c siphash/siphash.c blake/blake2b-ref.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ proof_verification.c siphash/siphash.c blake/blake2b-ref.c

clean:
	$(RM) proof
