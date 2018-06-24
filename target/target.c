/********************************************************************
Victim code.

gcc target.c -o target -std=gnu99 && ./target
 ********************************************************************/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <x86intrin.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <sys/mman.h>
#include <unistd.h> //getpid()

#ifdef MAP_HUGETLB
#define HUGEPAGES MAP_HUGETLB
#endif

#define SECRET_LEN 256
#define SECRET_REPEAT 20

//#define DEBUG
//#define SELF_FLUSH

#define NSLICES 4
#if NSLICES == 4
	#define ADDR2SET(x) 	(int)(((uint64_t)x >> 6) & 0x7ff)
	#define RAWSET(set) 	(set & 0x7ff)
	#define SLICESBITS 		11
#elif NSLICES == 8
	#define ADDR2SET(x) 	(int)(((uint64_t)x >> 6) & 0x3ff)
	#define RAWSET(set) 	(set & 0x3ff)
	#define SLICESBITS 		10
#endif

unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];
uint8_t* array2 = MAP_FAILED;

//char secret[] = "The Magic Words are Squeamish Ossifrage."; //Original
char secret[SECRET_LEN * SECRET_REPEAT];
char secret_permutation[] = {205, 254, 103,   3, 123,  64,  53, 224,  57,  32,  22, 249,  20,
		130, 241,  75, 170,  76,  66, 178,  62, 190, 237,   6, 191, 132,
		47,  17,  34, 118, 165, 204,  69,  92,  91,  51,  21, 115, 202,
		144, 166,  40, 236,  31,  59,  12, 247, 199, 139, 231, 138,  27,
		5,  46,  23,  43,  90,  24,  41, 160, 113, 253, 222,   8, 112,
		255,  39, 175, 173, 201,  97, 124, 117, 235, 155,  82, 193,  84,
		127, 242, 163, 218, 135, 184, 232, 153, 212, 159,  30,  73,  54,
		150,  79,  96,   7, 154,  44,  35,  83, 223, 214,   2, 186, 176,
		156,  42,  80,  87, 129, 198,  94, 120, 207,  88, 220,  67, 188,
		238, 142, 213,  15, 131, 251,   4, 228,  61,  89, 195,  33,  52,
		18, 164, 110, 183, 107, 133, 180, 128, 177, 215,  70, 210, 125,
		194,  55,  28, 211, 219,  60, 240,  49, 106, 137,  37, 140,  26,
		151, 122, 152, 114,  81,  86,  72,  77, 171,  74, 111, 250,  11,
		248, 102, 227, 206,  85,  65,   9, 162, 109,  93,  38, 225, 143,
		233, 230, 121, 149, 161,  95, 246, 126, 148, 145, 192, 189, 239,
		244, 141,  45, 169, 217, 146, 119, 197,  36, 100, 134, 181,  99,
		182, 226,  58,  56, 245, 104,  98,  50, 116,   0,  25, 221,  68,
		108, 136, 174, 243, 200, 179,  10,  71, 158, 229, 185,  48, 203,
		252,  78, 208, 168, 101, 209,  16,  13, 234,  14,  19, 105,   1,
		29, 157, 172, 147, 187, 167, 196, 216,  63};


__always_inline int memaccess(void *v) {
	int rv;
	asm volatile("mov (%1), %0": "+r" (rv): "r" (v):);
	return rv;
}

#ifdef DEBUG
void info(){
	printf("Debug Info\n");
	printf("pid = %d\n",getpid());

	char cmd [200];
	uint64_t malicious_x = (uint64_t) ((uint64_t)secret - (uint64_t) array1); /* default for malicious_x */
	printf("secret addr = %p\n",secret);
	printf("initial malicious_x = %lu\n",malicious_x);
	printf("array1_size addr = %p, set = %d\n",&array1_size,ADDR2SET(&array1_size));

	sprintf(cmd,"sudo ~/virt_to_phys_user %d %p",getpid(),&array1_size);
	system(cmd);
}
#endif

uint8_t victim_function(size_t x)
{
	if (x < array1_size) {
		memaccess(&array2[array1[x] * 64]);//MAGIC_BYTE;
		return 0;
	}
	return 1;
}


int main(int argc, const char **argv){
	int socket_desc , client_sock , c , read_size;
	struct sockaddr_in server , client;
	char client_message[64];

	int bufsize = 1024*1024;
	array2 = mmap(NULL, bufsize, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|HUGEPAGES, -1, 0);
	if (MAP_FAILED == array2){
		printf("Map Failed\n");
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < SECRET_LEN * SECRET_REPEAT; i++){
		secret[i] = secret_permutation[i % SECRET_LEN];
	}

#ifdef DEBUG
	info();
#endif

	for (size_t i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);

	if (socket_desc == -1){
		printf("Could not create socket");
	}
	puts("Socket created");

	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( 8888 );

	//Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0){
		//print the error message
		perror("bind failed. Error");
		return 1;
	}
	puts("bind done");

	while(1){
		//Listen
		listen(socket_desc , 3);

		//Accept and incoming connection
		puts("Waiting for incoming connections...");
		c = sizeof(struct sockaddr_in);

		//accept connection from an incoming client
		client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
		if (client_sock < 0){
			perror("accept failed");
			return 1;
		}
		puts("Connection accepted");

		//Receive a message from client
		while( (read_size = recv(client_sock , client_message , sizeof(size_t) , 0)) > 0 ){
			char result;
			result = victim_function(*(size_t*)client_message);

#ifdef SELF_FLUSH
			_mm_clflush((void const *)&array1_size); //attack should work without this line... define SELF_FLUSH for debug
#endif

		}


		for(int i=0;i<SECRET_LEN;i++){
			printf("%d, ",secret[i]);
		}

		if(read_size == 0){
			puts("Client disconnected");
			fflush(stdout);
		} else if(read_size == -1){
			perror("recv failed");
		}
	}
	return 0;
}
