#include "blake/blake2.h"
#include "siphash/siphash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Util to remove a substring from the read line in the log file */
char *strremove(char *str, const char *sub)
{
	char *p, *q, *r;
	if (*sub && (q = r = strstr(str, sub)) != NULL) {
		size_t len = strlen(sub);
		while ((r = strstr(p = r + len, sub)) != NULL) {
			memmove(q, p, r - p);
			q += r - p;
		}
		memmove(q, p, strlen(p) + 1);
	}
	return str;
}

int main(int argc, char **argv)
{
	siphash_key_t first_key;
	char *endptr, *line = NULL, *proof_in_log;
	size_t read, leng;
	static size_t key_len = sizeof(first_key);
	int ret;
	blake2b_state blake_state;

	/* Declare first secret key from program input */
	char *input_key = argv[1];

	/* Curate key from command line input to siphash_key type */
	int len = strlen(input_key);
	int len1 = len / 2;
	int len2 = len - len1;
	char *s1 = malloc(len1 + 1);
	memcpy(s1, input_key, len1);
	s1[len1] = '\0';
	char *s2 = malloc(len2 + 1);
	memcpy(s2, input_key + len1, len2);
	first_key.key[0] = strtoull(s1, &endptr, 16);
	first_key.key[1] = strtoull(s2, &endptr, 16);

	/* Open path of audit log passed from the command line for reading */
	FILE *log_file = fopen(argv[2], "r");

	printf("Initial key: %lx%lx\n", first_key.key[0], first_key.key[1]);

	/* Read the input trace line by line (each line is a log record) */
	while ((read = getline(&line, &leng, log_file)) != -1) {
		if (line[read - 1] == '\n')
			line[--read] = '\0';

		/* Snip the proof off from each audit log record */
		proof_in_log = strstr(line, " p=");

		/* If the audit record lacks a proof, Kenny Loggings is not activated yet, we abstain from proof verification */
		if (proof_in_log != NULL) {
			char *log_msg, *final;
			uint64_t regenerated_integrity_proof, integrity_proof_logged;
			size_t log_msg_len;

			/* Convert char string proof to uint64 type. Actual proof begins 3 bytes from " p=" */
			integrity_proof_logged = strtoull(proof_in_log + 3, &endptr, 16);
			printf("Proof      : %lx\n", integrity_proof_logged);

			/* Actual record for which proof is generated begins after message type */
			log_msg = strremove(line, proof_in_log);
			final = strstr(log_msg, "audit(");
			log_msg_len = strlen(final);

			/* Initialize a hash state S to hash a message to an output of outlen bytes, without using a key */
			ret = blake2b_init(&blake_state, key_len);
			if (ret != 0) {
				printf("Error blake2b_init (%d)\n", ret);
				break;
			}

			/* Hash the input buffer in of length inlen bytes into the hash state S */
			ret = blake2b_update(&blake_state, (uint8_t *)&first_key, key_len);
			if (ret != 0) {
				printf("Error blake2b_update (%d)\n", ret);
				break;
			}

			/* Functions compute the hash value accumulated in S and store it into out. 
            outlen must have the same value that was passed to the corresponding init function */
			ret = blake2b_final(&blake_state, (uint8_t *)&first_key, key_len);
			if (ret != 0) {
				printf("Error blake2b_final (%d)\n", ret);
				break;
			}

			/* SipHash computes a 64-bit message authentication code from a variable-length message and 128-bit secret key */
			regenerated_integrity_proof = siphash(final, log_msg_len, &first_key);
			printf("Regenerated: %lx\n", regenerated_integrity_proof);

			/* Compare regenerated proof through siphash and logged proof */
			if (integrity_proof_logged == regenerated_integrity_proof) {
				printf("Integrity of proof is valid\n");
			} else {
				printf("ALERT: Integrity of proof is invalid\n");
				#ifdef DEBUG
					printf("Log Message: %s\n",final);
				#endif
			}
		}
	}

	return ret;
}