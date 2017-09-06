#ifndef _LAST_ROUND_ATTACK_H
#define _LAST_ROUND_ATTACK_H

#include <libflush/libflush.h>
#define AES128_KEY_LEN 16
#define KEYBYTES 256
#define MAX_BUF 1024
#define MAX_PLAIN_TEXTS 3000
#define T_TABLE_ENTRIES 256

typedef unsigned char U8;

struct last_round_attack_args {
	int plain_text_cnt;				/* plaintext count */
	int cpu_cycle_threshold;		/* cpu cycle threshold */
	int cache_line_size;			/* cache line size. It's 64 byte for ARM generally */
	unsigned int off_te4;			/* offset for te4 */
	unsigned int off_rcon;			/* offset for rcon */
	char crypto_lib[MAX_BUF];		/* filepath of crypto library */
	char plaintext_file[MAX_BUF];	/* filepath of plaintexts */
};

struct last_round_attack_cache_ctx {
	struct last_round_attack_args args;							/* arguments for one_round_attack */
	libflush_session_t* libflush_session;						/* libflush session */
	int crypto_lib_fd;											/* fd for crypto library */
	U8 *crypto_lib_addr;										/* mapped address for crypto library */
	unsigned int crypto_lib_size;								/* mapped size for crypto library */
	unsigned int *state_te4;									/* address of te4 */
	unsigned int *state_rcon;									/* address for rcon */
	U8 plains[MAX_PLAIN_TEXTS][AES128_KEY_LEN];					/* plaintexts */
	unsigned int score[AES128_KEY_LEN][KEYBYTES];				/* candidate score */
};

struct last_round_attack_result {
	U8 predict_key[AES128_KEY_LEN];								/* result of attack. predicted aes key */
};

struct last_round_attack_ctx {
	struct last_round_attack_args args;
	struct last_round_attack_cache_ctx cache_ctx;
	struct last_round_attack_result result;
	int (*encrypt)(unsigned char *in, unsigned char *out, int size);	/* callback function to trigger encryption */
};

int last_round_attack_init(struct last_round_attack_ctx *ctx);
void last_round_attack_do_attack(struct last_round_attack_ctx *ctx);
void last_round_attack_finalize(struct last_round_attack_ctx *ctx);

#endif