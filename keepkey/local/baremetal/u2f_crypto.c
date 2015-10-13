/*
*******************************************************************************    
*   Portable FIDO U2F implementation
*   KeepKey specific initialization
*   (c) 2015 Ledger
*   
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

#include <stdint.h>
#include <string.h>
#include <rand.h>
#include "nist256p1.h"
#include "bignum.h"
#include "ecdsa.h"
#include "sha2.h"
#include "storage.h"
#include "bip32.h"
#include "aes.h"
#include "u2f_crypto.h"

static uint8_t privateKeySession[32];
static SHA256_CTX sha256;

bool compare_constantTime(const uint8_t *a, const uint8_t *b, uint16_t length) {
		uint16_t givenLength = length;
		uint8_t status = 0;
		uint16_t counter = 0;

		if (length == 0) {
			return false;
		}
		while ((length--) != 0) {
			status |= a[length] ^ b[length];
			counter++;
		}
		if (counter != givenLength) {
			return false;
		}
		return ((status == 0) ? true : false);
}

void u2f_crypto_init() {
}

bool u2f_crypto_available() {
	HDNode node;
	if (!storage_is_u2f_initialized()) {
		return false;
	}
	if (storage_has_pin() && !session_is_pin_cached()) {
		return false;
	}
	if (!storage_get_root_node(&node)) {
		return false;
	}	
	return true;
}

void encrypt_decrypt_unique_key_data(uint8_t *nonce, uint8_t *data, uint16_t length, uint8_t *target, bool encrypt) {
	HDNode node;
	aes_encrypt_ctx ctx;
	uint32_t address[] = { 0x8000000D, 0x80f1d001 };
	uint8_t nonceLocal[16];
	storage_get_root_node(&node);
	hdnode_private_ckd_cached(&node, address, 2);
	aes_encrypt_key256(node.private_key, &ctx);
	if (encrypt) {
		random_buffer(nonceLocal, 16);
		memcpy(nonce, nonceLocal, 16);
	}
	else {
		memcpy(nonceLocal, nonce, 16);
	}
	aes_ofb_crypt(data, target, length, nonceLocal, &ctx);
}

void derive_private_key_for_application_parameter(uint8_t *applicationParameter, uint8_t *privateKey) {
	uint32_t address[5];
	uint8_t i;
	HDNode node;
	storage_get_root_node(&node);
	address[0] = 0x8000000D;
	for (i=0; i<4; i++) {
		address[i + 1] = ((applicationParameter[4 * i] << 24) |
			      (applicationParameter[4 * (i + 1)] << 16) |
			      (applicationParameter[4 * (i + 2)] << 8) |
			      applicationParameter[4 * (i + 3)]);
	}
	hdnode_private_ckd_cached(&node, address, 5);
	memcpy(privateKey, node.private_key, 32);
}

uint16_t u2f_crypto_copy_attestation_certificate(uint8_t *buffer) {
	memcpy(buffer, storage_get_attestation_certificate(), storage_get_attestation_certificate_size());
	return storage_get_attestation_certificate_size();
}

static uint16_t u2f_wrap(const uint8_t *applicationParameter, uint8_t *keyHandle) {	
	memcpy(keyHandle + 16, applicationParameter, 32);
	encrypt_decrypt_unique_key_data(keyHandle, keyHandle + 16, 32, keyHandle + 16, true);
	return 48;
}

static bool u2f_unwrap(const uint8_t *keyHandle, uint16_t keyHandleLength, uint8_t *applicationParameter, uint8_t *privateKey) {
	if (keyHandleLength != 48) {
		return false;
	}
	encrypt_decrypt_unique_key_data((uint8_t*)keyHandle, (uint8_t*)(keyHandle + 16), 32, applicationParameter, false);	
	derive_private_key_for_application_parameter(applicationParameter, privateKey);
	return true;
}

uint16_t u2f_crypto_generate_key_and_wrap(const uint8_t *applicationParameter, uint8_t *publicKey, uint8_t *keyHandle) {		
	derive_private_key_for_application_parameter((uint8_t*)applicationParameter, privateKeySession);
	ecdsa_get_public_key65(&nist256p1, privateKeySession, publicKey);
	memset(privateKeySession, 0, 32);
	uint16_t length = u2f_wrap(applicationParameter, keyHandle);
	return length;
}

bool u2f_crypto_unwrap(const uint8_t *keyHandle, uint16_t keyHandleLength, const uint8_t *applicationParameter) {
	uint8_t applicationParameterLocal[32];
	if (!u2f_unwrap(keyHandle, keyHandleLength, applicationParameterLocal, privateKeySession)) {
		memset(privateKeySession, 0, 32);
		return false;
	}
	if (!compare_constantTime(applicationParameterLocal, applicationParameter, 32)) {
		memset(privateKeySession, 0, 32);
		return false;
	}
	return true;
}

bool u2f_sign_init(void) {
	sha256_Init(&sha256);
	return true;
}

bool u2f_sign_update(const uint8_t *message, uint16_t length) {
	sha256_Update(&sha256, message, length);
	return true;
}

static uint16_t u2f_crypto_sign(const uint8_t *privateKey, uint8_t *signature) {
	uint8_t hash[32];
	uint8_t signatureFlat[64];
	sha256_Final(hash, &sha256);
	if (ecdsa_sign_digest(&nist256p1, privateKey, hash, signatureFlat, NULL)) {
		return 0;
	}
	return ecdsa_sig_to_der(signatureFlat, signature);
}

uint16_t u2f_crypto_sign_application(uint8_t *signature) {
	return u2f_crypto_sign(privateKeySession, signature);
}

uint16_t u2f_crypto_sign_attestation(uint8_t *signature) {	
	uint16_t length = u2f_crypto_sign(storage_get_attestation_key(), signature);
	memset(privateKeySession, 0, 32);
	return length;
}

void u2f_crypto_reset() {
	memset(privateKeySession, 0, 32);
}

