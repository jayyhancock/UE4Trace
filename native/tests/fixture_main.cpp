#include <cstdio>
#include <cstdint>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
extern "C" const char* FixtureProfile(const char*);
extern "C" int FixtureTick();
extern "C" uint64_t FixtureCount();
volatile sig_atomic_t running=1;
void stop(int){running=0;}
int main(int argc,char** argv){
    setvbuf(stdout,nullptr,_IONBF,0);signal(SIGTERM,stop);signal(SIGINT,stop);
    const char* profile=FixtureProfile(argv[0]);
    if(argc>1){FILE* f=fopen(argv[1],"w");if(!f){perror("profile");return 2;}fputs(profile,f);fclose(f);}else puts(profile);
    if(argc>2){void* h=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);if(!h){fprintf(stderr,"dlopen: %s\n",dlerror());return 3;}}
    printf("fixture pid=%d ready\n",getpid());
    uint64_t ticks=0;while(running){if(FixtureTick()!=0){fprintf(stderr,"FAIL: original was not called exactly twice (nested pair)\n");return 4;}ticks++;if(ticks%100==0)printf("PASS ticks=%llu original_calls=%llu\n",(unsigned long long)ticks,(unsigned long long)FixtureCount());usleep(10000);}
    printf("FINAL ticks=%llu original_calls=%llu expected=%llu\n",(unsigned long long)ticks,(unsigned long long)FixtureCount(),(unsigned long long)(ticks*2));return FixtureCount()==ticks*2?0:5;
}
