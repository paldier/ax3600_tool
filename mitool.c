/*
*
* Copyright (C) 2020-2021, paldier<paldier@hotmail.com>.
*
*${CORSS_PREFIX}gcc -static mitool.c -o mitool
*${CORSS_PREFIX}strip mitool
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
 
#define BUFSIZE     65532

struct model_s {
	char *pid;
	char *model;
};

static const struct model_s model_list[] = {
	{ "RA67", "AX5" },//redmi
	{ "RA69", "AX6" },//redmi
	{ "RA70", "AX9000" },//xiaomi
	{ "RA72", "AX6000" },//xiaomi
	{ "RA81", "AX3000" },//redmi
	{ "RM1800", "AX1800" },//xiaomi
	{ "R1800", "AX1800" },//xiaomi
	{ "R3600", "AX3600" },//xiaomi
	{ NULL, NULL },
};

typedef struct
{
	unsigned int count[2];
	unsigned int state[4];
	unsigned char buffer[64];
}MD5_CTX;


#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
#define FF(a,b,c,d,x,s,ac) \
{ \
	a += F(b,c,d) + x + ac; \
	a = ROTATE_LEFT(a,s); \
	a += b; \
}
#define GG(a,b,c,d,x,s,ac) \
{ \
	a += G(b,c,d) + x + ac; \
	a = ROTATE_LEFT(a,s); \
	a += b; \
}
#define HH(a,b,c,d,x,s,ac) \
{ \
	a += H(b,c,d) + x + ac; \
	a = ROTATE_LEFT(a,s); \
	a += b; \
}
#define II(a,b,c,d,x,s,ac) \
{ \
	a += I(b,c,d) + x + ac; \
	a = ROTATE_LEFT(a,s); \
	a += b; \
}
unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void MD5Init(MD5_CTX *context)
{
	context->count[0] = 0;
	context->count[1] = 0;
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
}

void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{
	unsigned int i = 0,j = 0;
	while(j < len)
	{
		output[j] = input[i] & 0xFF;
		output[j+1] = (input[i] >> 8) & 0xFF;
		output[j+2] = (input[i] >> 16) & 0xFF;
		output[j+3] = (input[i] >> 24) & 0xFF;
		i++;
		j+=4;
	}
}
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)
{
	unsigned int i = 0,j = 0;
	while(j < len)
	{
		output[i] = (input[j]) |
			(input[j+1] << 8) |
			(input[j+2] << 16) |
			(input[j+3] << 24);
		i++;
		j+=4;
	}
}
void MD5Transform(unsigned int state[4],unsigned char block[64])
{
	unsigned int a = state[0];
	unsigned int b = state[1];
	unsigned int c = state[2];
	unsigned int d = state[3];
	unsigned int x[64];
	MD5Decode(x,block,64);
	FF(a, b, c, d, x[ 0], 7, 0xd76aa478); /* 1 */
	FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
	FF(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
	FF(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
	FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); /* 5 */
	FF(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
	FF(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
	FF(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
	FF(a, b, c, d, x[ 8], 7, 0x698098d8); /* 9 */
	FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
	FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
	FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

	/* Round 2 */
	GG(a, b, c, d, x[ 1], 5, 0xf61e2562); /* 17 */
	GG(d, a, b, c, x[ 6], 9, 0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[ 5], 5, 0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], 9,  0x2441453); /* 22 */
	GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
	GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
	GG(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH(a, b, c, d, x[ 5], 4, 0xfffa3942); /* 33 */
	HH(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[ 1], 4, 0xa4beea44); /* 37 */
	HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */
	HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II(a, b, c, d, x[ 0], 6, 0xf4292244); /* 49 */
	II(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
	II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[ 4], 6, 0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen)
{
	unsigned int i = 0,index = 0,partlen = 0;
	index = (context->count[0] >> 3) & 0x3F;
	partlen = 64 - index;
	context->count[0] += inputlen << 3;
	if(context->count[0] < (inputlen << 3))
		context->count[1]++;
	context->count[1] += inputlen >> 29;

	if(inputlen >= partlen)
	{
		memcpy(&context->buffer[index],input,partlen);
		MD5Transform(context->state,context->buffer);
		for(i = partlen;i+64 <= inputlen;i+=64)
			MD5Transform(context->state,&input[i]);
		index = 0;
	}
	else
	{
		i = 0;
	}
	memcpy(&context->buffer[index],&input[i],inputlen-i);
}

void MD5Final(MD5_CTX *context,unsigned char digest[16])
{
	unsigned int index = 0,padlen = 0;
	unsigned char bits[8];
	index = (context->count[0] >> 3) & 0x3F;
	padlen = (index < 56)?(56-index):(120-index);
	MD5Encode(bits,context->count,8);
	MD5Update(context,PADDING,padlen);
	MD5Update(context,bits,8);
	MD5Encode(digest,context->state,16);
}

static void usage(void)
{
	fprintf(stderr, "Copyright (c) 2020-2021, paldier<paldier@hotmail.com>.\n");
	fprintf(stderr, "Usage: mitool\n");
	fprintf(stderr, "mitool lock\n");
	fprintf(stderr, "\tlock mtd9 and auto reboot\n");
	fprintf(stderr, "mitool unlock\n");
	fprintf(stderr, "\tunlock mtd9 and auto reboot\n");
	fprintf(stderr, "mitool password\n");
	fprintf(stderr, "\tprintf default password\n");
	fprintf(stderr, "mitool hack\n");
	fprintf(stderr, "\tset ssh telnet uart to default enable\n");
	fprintf(stderr, "mitool model\n");
	fprintf(stderr, "\tshow model\n");
}

static const unsigned int crc32tab[] = {
 0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
 0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
 0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
 0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
 0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
 0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
 0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
 0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
 0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
 0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
 0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
 0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
 0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
 0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
 0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
 0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
 0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
 0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
 0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
 0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
 0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
 0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
 0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
 0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
 0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
 0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
 0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
 0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
 0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
 0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
 0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
 0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
 0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
 0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
 0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
 0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
 0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
 0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
 0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
 0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
 0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
 0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};
 
 
static unsigned int crc32( const unsigned char *buf, unsigned int size)
{
     unsigned int i, crc;
     crc = 0xFFFFFFFF;
 
 
     for (i = 0; i < size; i++)
      crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
 
     return crc^0xFFFFFFFF;
}
 

unsigned char temp_str[30];
unsigned char password[30];
void ReadStrUnit(unsigned char * str, unsigned char *temp_str,int idx,int len)
{
    int index = 0;
    for(index; index < len; index++)
    {
        temp_str[index] = str[idx+index];
    }
    temp_str[index] = '\0';
}

int GetSubStrPos(unsigned char *str1, unsigned char *str2)
{
    int idx = 0;
    int len1 = BUFSIZE;
    int len2 = strlen(str2);

    if( len1 < len2)
        return -1;

    while(1)
    {
        ReadStrUnit(str1,temp_str,idx,len2);
        if(strcmp(str2,temp_str)==0)break;
        idx++;
        if(idx>=len1)return -1;
    }

    return idx;
}

int atoe(unsigned char *a, unsigned char *e)
{
	int i;
	unsigned char temp[3] = {0};
	memset(e, 0, 4);
	for (i = 0; i < 4; i++) {
		memset(temp, 0, sizeof(temp));
		memcpy(temp, a + (i*2), 2);
		e[i] = strtoul(temp, NULL, 16);
	}
	return 0;
}

static int check_mtd9(void)
{
	int minor;
	unsigned int size, erasesize;
	char name[65];
	char line[128];
	FILE *fp = fopen("/proc/mtd", "r");
	if (fp == NULL)
		return -1;
	while (fgets(line, sizeof(line), fp)){
		if (sscanf(line, "mtd%d: %x %x \"%64[^\"]\"", &minor, &size, &erasesize, name) == 4 && strcmp(name, "bdata") == 0){
			if (minor==9){
				fclose(fp);
				return 1;
			}
		}
	}
	fclose(fp);
	return -1;
}


unsigned char buf[BUFSIZE];
unsigned char buff[99];
static int load_buf(void)
{
	FILE *fd;
	if(check_mtd9()<0){
		printf("特殊版分区暂不支持\n");
		return -1;
	}
	fd = fopen("/dev/mtd9", "rb");
	if (fd < 0)
		return -1;
	memset(buf, 0, sizeof(buf));
	fseek(fd, 4, SEEK_SET);
	fread(buf, BUFSIZE, 1,fd);
	fclose(fd);
	return 0;
}

static int lock_mtd(int t)
{
	FILE *fd;
	int r;
	unsigned char temp[4];
	fd = fopen("/dev/mtd10", "rb");
	if (fd < 0)
		return -1;
	if(!check_mtd9()){
		printf("特殊版分区暂不支持\n");
		return -1;
	}
	memset(temp, 0, sizeof(temp));
	fseek(fd, 0, SEEK_SET);
	fread(temp, 4, 1,fd);
	fclose(fd);
	if(t==0 ){
		if(temp[0]!=0xA5){
			temp[0]=0xA5;
			temp[1]=0x5A;
			temp[2]=0x0;
			temp[3]=0x0;
			fd = fopen("/dev/mtdblock10", "wb");
			if (fd < 0)
				return -1;
			fseek(fd, 0, SEEK_SET);
			r=fwrite(temp, 1, 4,fd);
			fclose(fd);
			system("/sbin/reboot");
		}
		printf("mtd unlocked\n");
	}else{
		if(temp[0]!=0xFF){
			temp[0]=0xFF;
			temp[1]=0xFF;
			temp[2]=0xFF;
			temp[3]=0xFF;
			fd = fopen("/dev/mtdblock10", "wb");
			if (fd < 0)
				return -1;
			fseek(fd, 0, SEEK_SET);
			r=fwrite(temp, 1, 4,fd);
			fclose(fd);
			system("/sbin/reboot");
		}
		printf("mtd locked\n");
	}

}

char *get_model(char *pid)
{
	char *model = "unknown";
	const struct model_s *p;

	for (p = &model_list[0]; p->pid; ++p) {
		if (!strcmp(pid, p->pid)) {
			model = p->model;
			break;
		}
	}
	return model;
}

static int model_show(void)
{
	int i;

	if(load_buf()<0)
		return -1;
	i = GetSubStrPos(buf,"model");
	printf("model=%s\n", get_model(&buf[i+6]));
}

static int password_show(void)
{
	int i,j;
	unsigned char decrypt[16];
	unsigned char sn[99];
	unsigned char salt[]="6d2df50a-250f-4a30-a5e6-d44fb0960aa0";
 	unsigned char c3[]="SN=";
	if(load_buf()<0)
		return -1;
	i = GetSubStrPos(buf,c3);
	for(j=0;j<15;j++){
		sprintf(&sn[j], "%c", buf[i+3+j]);//sn
	}
	memset(buff, 0, sizeof(buff));
	sprintf(buff, "%s%s", sn, salt);
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5,buff,strlen(buff));
	MD5Final(&md5,decrypt);
	memset(password, 0, sizeof(password));
	for(i=0;i<4;i++)
	{
		sprintf(&password[i*2],"%02x",decrypt[i]);
	}
}

static int calc_img_crc()
{
	FILE *fd;
	int i,j;
	unsigned int crc = 0xffffffff; 
 	unsigned char c[]="ssh_en";
 	unsigned char c1[]="telnet_en";
 	unsigned char c2[]="uart_en";

	if(load_buf()<0)
		return -1;
	i = GetSubStrPos(buf,"model");
	printf("model=%s\n", get_model(&buf[i+6]));
	i = GetSubStrPos(buf,c);
	printf("get ssh_en=%c",buf[i+7]);
	buf[i+7]='1';//ssh
	i = GetSubStrPos(buf,c1);
	printf(" telnet_en=%c",buf[i+10]);
	buf[i+10]='1';//telnet
	i = GetSubStrPos(buf,c2);
	printf(" uart_en=%c\n",buf[i+8]);
	buf[i+8]='1';//uart
	fd = fopen("/dev/mtdblock9", "wb");
	if (fd < 0)
		return -1;
	fseek(fd, 4, SEEK_SET);
	fwrite(buf, 1, BUFSIZE, fd);
	crc = crc32(buf, BUFSIZE);
	memset(buf, 0, sizeof(buf));
	memset(buff, 0, sizeof(buff));
	snprintf(buff, sizeof(buff), "%08X", crc);
	atoe(buff, buf);
	memset(buff, 0, sizeof(buff));
	buff[0]=buf[3];
	buff[1]=buf[2];
	buff[2]=buf[1];
	buff[3]=buf[0];
	fseek(fd, 0, SEEK_SET);
	fwrite(buff, 1, 4, fd);
	fclose(fd);
	system("sed -i 's/channel=.*/channel=\"debug\"/g' /etc/init.d/dropbear");
	return 0;
}
 
int main(int argc, char **argv)
{
	int ret;
	if (argc != 2)
		usage();
	else if (!strcmp(argv[1], "hack")) {
		ret = calc_img_crc();
		if (ret < 0) {
			exit(1);
		}
		password_show();
		printf("set ssh_en=1 telnet_en=1 uart_en=1\nNOTE!!! ssh default usesrname:root password:%s\n",password);
		printf("automatic lock mtd and reboot\n");
		lock_mtd(1);
	} else if (!strcmp(argv[1], "lock"))
		lock_mtd(1);
	else if (!strcmp(argv[1], "unlock"))
		lock_mtd(0);
	else if (!strcmp(argv[1], "password")){
		password_show();
		printf("ssh default usesrname:root password:%s\n",password);
	} else if (!strcmp(argv[1], "model")){
		model_show();
	} else
		usage();
 
	return 0;
}

