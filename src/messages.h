/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_MESSAGES_H
#define _WG_MESSAGES_H

#ifdef SUPPORTS_CURVE
#include <zinc/curve25519.h>
#endif /* SUPPORTS_CURVE */
#include <zinc/chacha20poly1305.h>
#include <zinc/blake2s.h>
#ifdef SUPPORTS_PQC
#include <kyber/params.h>
#endif /* SUPPORTS_PQC */

#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/skbuff.h>

#ifndef CURVE25519_KEY_SIZE
#define CURVE25519_KEY_SIZE 32
#endif

enum noise_lengths {
	NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_SIZE,
	NOISE_TIMESTAMP_LEN = sizeof(u64) + sizeof(u32),
	NOISE_AUTHTAG_LEN = CHACHA20POLY1305_AUTHTAG_SIZE,
	NOISE_HASH_LEN = BLAKE2S_HASH_SIZE
};

#ifdef SUPPORTS_PQC
enum noise_pq_lengths {
	NOISE_PQ_SECRET_KEY_LEN = KYBER_SECRETKEYBYTES,
	NOISE_PQ_PUBLIC_KEY_LEN = KYBER_PUBLICKEYBYTES,
	NOISE_PQ_CIPHERTEXT_LEN = KYBER_CIPHERTEXTBYTES,
	NOISE_PQ_EPHEMERAL_PUBLIC_KEY_LEN = KYBER_PUBLICKEYBYTES,
	NOISE_PQ_EPHEMERAL_SECRET_KEY_LEN = KYBER_SECRETKEYBYTES,
	NOISE_PQ_EPHEMERAL_CIPHERTEXT_LEN = KYBER_CIPHERTEXTBYTES,
	NOISE_PQ_PUBLIC_KEY_HASH_LEN = NOISE_PUBLIC_KEY_LEN // needs to be the same as the public key (32B)
};
#endif /* SUPPORTS_PQC */

#define noise_encrypted_len(plain_len) ((plain_len) + NOISE_AUTHTAG_LEN)

enum cookie_values {
	COOKIE_SECRET_MAX_AGE = 2 * 60,
	COOKIE_SECRET_LATENCY = 5,
	COOKIE_NONCE_LEN = XCHACHA20POLY1305_NONCE_SIZE,
	COOKIE_LEN = 16
};

enum counter_values {
	COUNTER_BITS_TOTAL = 8192,
	COUNTER_REDUNDANT_BITS = BITS_PER_LONG,
	COUNTER_WINDOW_SIZE = COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS
};

enum limits {
	REKEY_AFTER_MESSAGES = 1ULL << 60,
	REJECT_AFTER_MESSAGES = U64_MAX - COUNTER_WINDOW_SIZE - 1,
	REKEY_TIMEOUT = 5,
	REKEY_TIMEOUT_JITTER_MAX_JIFFIES = HZ / 3,
	REKEY_AFTER_TIME = 120,
	REJECT_AFTER_TIME = 180,
	INITIATIONS_PER_SECOND = 50,
	MAX_PEERS_PER_DEVICE = 1U << 20,
	KEEPALIVE_TIMEOUT = 10,
	MAX_TIMER_HANDSHAKES = 90 / REKEY_TIMEOUT,
	MAX_QUEUED_INCOMING_HANDSHAKES = 4096, /* TODO: replace this with DQL */
	MAX_STAGED_PACKETS = 128,
	MAX_QUEUED_PACKETS = 1024 /* TODO: replace this with DQL */
};

/*
 *  0-4 remain unchanged for retro compatibility
 */
enum message_type {
	MESSAGE_INVALID = 0,
#ifdef SUPPORTS_CURVE
    MESSAGE_HANDSHAKE_INITIATION = 1,
    MESSAGE_HANDSHAKE_RESPONSE = 2,
    MESSAGE_HANDSHAKE_COOKIE = 3,
#endif /* SUPPORTS_CURVE */
    MESSAGE_DATA = 4,
    _MESSAGE_PQ_BORDER = 5, // will exists in any version
#ifdef SUPPORTS_PQC
    MESSAGE_PQ_HANDSHAKE_INITIATION = 5,
    MESSAGE_PQ_HANDSHAKE_RESPONSE = 6,
    MESSAGE_PQ_HANDSHAKE_COOKIE = 7,
#endif /* SUPPORTS_PQC */
};

struct message_header {
	/* The actual layout of this that we want is:
	 * u8 type
	 * u8 reserved_zero[3]
	 *
	 * But it turns out that by encoding this as little endian,
	 * we achieve the same thing, and it makes checking faster.
	 */
	__le32 type;
};

struct message_macs {
	u8 mac1[COOKIE_LEN];
	u8 mac2[COOKIE_LEN];
};

#ifdef SUPPORTS_CURVE
struct message_handshake_initiation {
	struct message_header header;
	__le32 sender_index;
	u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 encrypted_static[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];
	u8 encrypted_timestamp[noise_encrypted_len(NOISE_TIMESTAMP_LEN)];
	struct message_macs macs;
};

struct message_handshake_response {
	struct message_header header;
	__le32 sender_index;
	__le32 receiver_index;
	u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 encrypted_nothing[noise_encrypted_len(0)];
	struct message_macs macs;
};
#endif /* SUPPORTS_CURVE */

struct message_handshake_cookie {
	struct message_header header;
	__le32 receiver_index;
	u8 nonce[COOKIE_NONCE_LEN];
	u8 encrypted_cookie[noise_encrypted_len(COOKIE_LEN)];
};

struct message_data {
	struct message_header header;
	__le32 key_idx;
	__le64 counter;
	u8 encrypted_data[];
};

#define message_data_len(plain_len) \
	(noise_encrypted_len(plain_len) + sizeof(struct message_data))

enum message_alignments {
	MESSAGE_PADDING_MULTIPLE = 16,
	MESSAGE_MINIMUM_LENGTH = message_data_len(0)
};

#define SKB_HEADER_LEN                                       \
	(max(sizeof(struct iphdr), sizeof(struct ipv6hdr)) + \
	 sizeof(struct udphdr) + NET_SKB_PAD)
#define DATA_PACKET_HEAD_ROOM \
	ALIGN(sizeof(struct message_data) + SKB_HEADER_LEN, 4)

enum { HANDSHAKE_DSCP = 0x88 /* AF41, plus 00 ECN */ };

#ifdef SUPPORTS_PQC
struct message_pq_handshake_initiation {
	struct message_header header;
	__le32 sender_index;
	u8 ciphertext[NOISE_PQ_CIPHERTEXT_LEN];
	u8 ephemeral_public[NOISE_PQ_EPHEMERAL_PUBLIC_KEY_LEN];
	u8 encrypted_static[noise_encrypted_len(NOISE_PQ_PUBLIC_KEY_HASH_LEN)];
	u8 encrypted_timestamp[noise_encrypted_len(NOISE_TIMESTAMP_LEN)];
	struct message_macs macs;
};

struct message_pq_handshake_response {
	struct message_header header;
	__le32 sender_index;
	__le32 receiver_index;
	u8 ciphertext[NOISE_PQ_CIPHERTEXT_LEN];
	u8 ephemeral_ciphertext[NOISE_PQ_EPHEMERAL_CIPHERTEXT_LEN];
	u8 encrypted_nothing[noise_encrypted_len(0)];
	struct message_macs macs;
};
#endif /* SUPPORTS_PQC */
#endif /* _WG_MESSAGES_H */
