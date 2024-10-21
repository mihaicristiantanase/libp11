/*
 * Copyright (c) 2020 Frank Morgner <frankmorgner@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "libp11-int.h"
#include <libp11.h>

static void error_queue(const char *name);
static void testKeyGen(int algo, int size, PKCS11_SLOT* slot);

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx;
	PKCS11_SLOT *slots, *slot;

	int rc = 0, token_found = 0;

	unsigned int nslots;

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s /usr/lib/opensc-pkcs11.so pin\n",
			argv[0]);
		return 1;
	}

	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");

	rc = PKCS11_CTX_load(ctx, argv[1]);
	error_queue("PKCS11_CTX_load");
	if (rc) {
		fprintf(stderr, "loading pkcs11 engine failed: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		goto nolib;
	}

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	if (rc < 0) {
		fprintf(stderr, "no slots available\n");
		goto noslots;
	}

	/* get slots with a token */
	for (slot = PKCS11_find_token(ctx, slots, nslots);
			slot != NULL;
			slot = PKCS11_find_next_token(ctx, slots, nslots, slot)) {
		token_found = 1;
		break;
	}
	if (!token_found) {
		error_queue("PKCS11_find_token");
		fprintf(stderr, "no token available\n");
		goto notoken;
	}

	// login
	rc  = PKCS11_open_session(slot, 1);
	error_queue("PKCS11_open_session");

	rc = PKCS11_login(slot, 0, argv[2]);
	error_queue("PKCS11_login");

	// generate some keys using RSA (implicit)
	testKeyGen(0, 128, slot);
	testKeyGen(0, 8192, slot);
	testKeyGen(0, 3000, slot);
	testKeyGen(0, 3000, slot);
	testKeyGen(0, 2048, slot);
	testKeyGen(0, 1024, slot);

	// generate some keys using RSA (explicit)
	testKeyGen(CKM_RSA_PKCS_KEY_PAIR_GEN, 128, slot);
	testKeyGen(CKM_RSA_PKCS_KEY_PAIR_GEN, 2048, slot);
	testKeyGen(CKM_RSA_PKCS_KEY_PAIR_GEN, 8192, slot);

	// generate some keys using EC
	testKeyGen(CKM_ECDSA_KEY_PAIR_GEN, 12, slot);
	testKeyGen(CKM_ECDSA_KEY_PAIR_GEN, 256, slot);
	testKeyGen(CKM_ECDSA_KEY_PAIR_GEN, 384, slot);
	testKeyGen(CKM_ECDSA_KEY_PAIR_GEN, 1024, slot);

	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);

	return 0;

notoken:
	PKCS11_release_all_slots(ctx, slots, nslots);

noslots:
	PKCS11_CTX_unload(ctx);

nolib:
	PKCS11_CTX_free(ctx);

	printf("listing failed.\n");
	return 1;
}

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}

void testKeyGen(int algo, int size, PKCS11_SLOT* slot) {
	char label[32] = {0};
	char idStr[32] = {0};
	unsigned char id[32] = {0};

	char testname[256] = {0};
	sprintf(testname, "* PKCS11_generate_key algo:0x%x size:%d", algo, size);

	sprintf(label, "test-key-0x%x-%d", algo, size);
	sprintf(idStr, "id-test-key-0x%x-%d", algo, size);
	memcpy(id, idStr, sizeof(idStr));
	int rc = PKCS11_generate_key(slot->token, algo, size, label, id, strlen(idStr));
	if (rc == 0) {
		printf("%s ·········→ Success.\n", testname);
	} else {
		error_queue(testname);
	}
}

/* vim: set noexpandtab: */
