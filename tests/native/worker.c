#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include <setjmp.h>
#include "../../src/monitor.c"

const int32_t vmk_ModuleCurrentID=97;
static union { uint64_t align;unsigned char bytes[0x110]; } cache;
static uint64_t ledgers[40];
static struct raw_resource rows[10];
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static pthread_t worker;
static int thread_created,heap_live,startup_pending,killed;
static unsigned pins,creates,destroys,maps,unmaps,sleeps,ticks,joins,world_destroys;
static unsigned cycle_reads,valid_records,invalid_records,parks;
static unsigned at_unpin,allow_publish,cleanup_waiting,stop_before_publish;
static unsigned long long stop_watermark;
static char logs[16384];
static size_t log_size;
static const char *scenario;
static void *heap_id=(void *)(uintptr_t)0x1000;
static void *default_heap;
static int32_t (*callback)(void *);
static void *callback_data;
static jmp_buf parked;
static int is(const char *value){return !strcmp(scenario,value);}
static void put64(unsigned off,uint64_t value){memcpy(cache.bytes+off,&value,8);}
static void put32(unsigned off,uint32_t value){memcpy(cache.bytes+off,&value,4);}

int32_t vmk_ACPIDeviceIterate(void *old,void **out){*out=old==(void *)UINTPTR_MAX?cache.bytes:NULL;return 0;}
int32_t vmk_ACPIQueryInfo(void *dev,struct probe_info *out){if(dev!=cache.bytes)abort();out->count=10;out->irqs=0;out->name=(char *)cache.bytes+0xc8;return 0;}
int32_t vmk_ACPIQueryIOResources(void *dev,uint32_t n,struct raw_resource *out){if(dev!=cache.bytes||n!=10)abort();for(unsigned i=0;i<10;++i)out[i]=rows[i];return 0;}
int32_t vmk_ModuleIncUseCount(int32_t id){if(id!=97)abort();pthread_mutex_lock(&lock);if(is("pin-rejected")&&thread_created&&pthread_equal(pthread_self(),worker)){pthread_mutex_unlock(&lock);return 0x0bad0003;}++pins;pthread_mutex_unlock(&lock);return 0;}
int32_t vmk_ModuleDecUseCount(int32_t id){if(id!=97)abort();pthread_mutex_lock(&lock);if(!pins)abort();--pins;if(is("publish-race")&&thread_created&&pthread_equal(pthread_self(),worker)){at_unpin=1;pthread_cond_broadcast(&changed);while(!allow_publish)pthread_cond_wait(&changed,&lock);}pthread_mutex_unlock(&lock);return 0;}
void *vmk_ModuleGetHeapID(int32_t id){if(id!=97)abort();return default_heap;}
void vmk_ModuleSetHeapID(int32_t id,void *h){if(id!=97||h!=heap_id||default_heap)abort();default_heap=h;}
int32_t vmk_NameInitialize(char *out,const char *name){if(strlen(name)>31)abort();strcpy(out,name);return 0;}
int32_t vmk_HeapCreate(struct heap_props *p,void **out){if(p->module!=97||p->maximum<16384||!pins)abort();++creates;if(is("null-heap")){*out=NULL;return 0;}heap_live=1;*out=heap_id;return 0;}
int32_t vmk_HeapDestroySync(void *h,int64_t timeout){if(h!=heap_id||!heap_live||startup_pending||thread_created||ledgers[17]||timeout!=1000)abort();++destroys;if(is("destroy-error"))return 1;heap_live=0;return 0;}
int32_t vmk_ACPIMapIOResource(int32_t id,void *dev,uint32_t index,struct mapped_resource *out){if(id!=97||dev!=cache.bytes||index!=4||!heap_live||!pins)abort();++maps;cycle_reads=0;ledgers[17]=1;ledgers[18]=UINT64_C(0x430010000000);out->type=2;out->va=ledgers[18];out->attrs=9;out->length=0x600000;return 0;}
int32_t vmk_ACPIUnmapIOResource(int32_t id,void *dev,uint32_t index){if(id!=97||dev!=cache.bytes||index!=4||!pins||!heap_live)abort();++unmaps;if(is("unmap-error"))return 1;ledgers[17]=ledgers[18]=0;return 0;}
int32_t vmk_MappedResourceRead8(const struct mapped_resource *m,uint64_t offset,uint8_t *out){if(m->type!=2||m->attrs!=9||!pins||!heap_live||++cycle_reads>16)abort();if(offset>=0x210400&&offset<=0x210405)*out=(uint8_t)"NUC_EC"[offset-0x210400];else if(offset==0x21041c)*out=1;else if(offset==0x21041d)*out=12;else if(offset==0x21041e)*out=53;else abort();return 0;}
static void log_message(const char *fmt,va_list ap){pthread_mutex_lock(&lock);int n=vsnprintf(logs+log_size,sizeof(logs)-log_size,fmt,ap);if(n<0||(size_t)n>=sizeof(logs)-log_size)abort();if(strstr(logs+log_size,"nuc_fan_monitor: stopping seq=")){sscanf(logs+log_size,"nuc_fan_monitor: stopping seq=%llu",&stop_watermark);stop_before_publish=!valid_records;}if(strstr(logs+log_size,"nuc_fan_monitor: sample ")){if(strstr(logs+log_size," valid=1 "))++valid_records;else ++invalid_records;}log_size+=(size_t)n;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&lock);}
void _vmk_LogMessage(const char *fmt,...){va_list ap;va_start(ap,fmt);log_message(fmt,ap);va_end(ap);}
void _vmk_WarningMessage(const char *fmt,...){va_list ap;va_start(ap,fmt);log_message(fmt,ap);va_end(ap);}
static void *entry(void *unused){(void)unused;pthread_mutex_lock(&lock);startup_pending=0;pthread_mutex_unlock(&lock);return (void *)(intptr_t)callback(callback_data);}
uint64_t vmk_WorldCreateAllocSize(uint64_t *alignment){*alignment=0;return 11096;}
int32_t vmk_WorldCreate(struct monitor_world_props *p,uint32_t *id){if(!heap_live||!pins||p->module!=97||p->sched_class!=1||p->heap!=heap_id||!p->name||!p->start)abort();if(is("create-error")){*id=0;return 1;}*id=is("zero-id")?0:123;startup_pending=1;callback=p->start;callback_data=p->data;if(!is("startup-timeout")&&!is("zero-id")){thread_created=1;if(pthread_create(&worker,NULL,entry,NULL))abort();}return 0;}
int32_t vmk_WorldDestroy(uint32_t id){if(id!=123)abort();++world_destroys;pthread_mutex_lock(&lock);killed=1;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&lock);return 0;}
int32_t vmk_WorldWaitForDeath(uint32_t id){if(id!=123)abort();pthread_mutex_lock(&lock);++joins;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&lock);if(is("join-once-error")&&joins==1)return 0x0bad0032;if(thread_created){if(pthread_join(worker,NULL))abort();thread_created=0;}return 0;}
int32_t vmk_WorldSleep(uint64_t us){
 if(us==1000000){++parks;longjmp(parked,1);}
 if(us!=30000000){pthread_mutex_lock(&lock);if(at_unpin&&!allow_publish){cleanup_waiting=1;pthread_cond_broadcast(&changed);}pthread_mutex_unlock(&lock);struct timespec tiny={0,10000};nanosleep(&tiny,NULL);return 0;}
 pthread_mutex_lock(&lock);++sleeps;pthread_cond_broadcast(&changed);
 while(ticks<sleeps&&!killed)pthread_cond_wait(&changed,&lock);
 int dead=killed;pthread_mutex_unlock(&lock);return dead?0x0bad0069:0;
}
static void wait_idle(unsigned count){pthread_mutex_lock(&lock);while(sleeps<count&&valid_records<count&&!invalid_records)pthread_cond_wait(&changed,&lock);while(sleeps<count&&!invalid_records)pthread_cond_wait(&changed,&lock);pthread_mutex_unlock(&lock);}
static void json_string(const char *text){putchar('"');for(;*text;++text){if(*text=='"'||*text=='\\')putchar('\\');if(*text=='\n')fputs("\\n",stdout);else putchar(*text);}putchar('"');}
static void *cleanup_entry(void *unused){(void)unused;cleanup_module();return (void *)(uintptr_t)1;}
int main(int argc,char **argv){
 if(argc!=2)return 2;scenario=argv[1];put32(0,0x41435049);put32(0x68,10);put64(0x80,0x140);put64(0x38,(uintptr_t)ledgers);strcpy((char *)cache.bytes+0xc8,"\\_SB_.PRRE");ledgers[16]=1;
 for(unsigned i=0;i<10;++i){rows[i].kind=0;rows[i].base=i*4096;rows[i].length=4096;}rows[4].base=0xfe200000;rows[4].length=0x600000;
 int status=init_module();unsigned idle_pins=99;int returned_cleanup=0;
 if(is("publish-race")){pthread_mutex_lock(&lock);while(!at_unpin)pthread_cond_wait(&changed,&lock);pthread_mutex_unlock(&lock);pthread_t cleaner;pthread_create(&cleaner,NULL,cleanup_entry,NULL);pthread_mutex_lock(&lock);while(!cleanup_waiting&&!joins)pthread_cond_wait(&changed,&lock);allow_publish=1;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&lock);void *done=NULL;pthread_join(cleaner,&done);returned_cleanup=done==(void *)(uintptr_t)1;}
 else if(is("create-error")||is("null-heap")){if(!pins){cleanup_module();returned_cleanup=1;}}
 else if(!is("startup-timeout")&&!is("zero-id")){
  if(is("unmap-error")||is("pin-rejected")){pthread_mutex_lock(&lock);while(!invalid_records)pthread_cond_wait(&changed,&lock);pthread_mutex_unlock(&lock);if(is("pin-rejected")){cleanup_module();returned_cleanup=1;}else if(thread_created){pthread_join(worker,NULL);thread_created=0;}}
  else {for(unsigned i=1;i<=3;++i){wait_idle(i);if(i<3){pthread_mutex_lock(&lock);ticks=i;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&lock);}}idle_pins=pins;if(!setjmp(parked)){cleanup_module();returned_cleanup=1;}}
 }
 printf("{\"status\":%d,\"pins\":%u,\"idle_pins\":%u,\"heap_live\":%d,\"creates\":%u,\"destroys\":%u,\"maps\":%u,\"unmaps\":%u,\"joins\":%u,\"world_destroys\":%u,\"valid\":%u,\"invalid\":%u,\"parks\":%u,\"cleanup_returned\":%d,\"stop_watermark\":%llu,\"stop_before_publish\":%u,\"log\":",status,pins,idle_pins,heap_live,creates,destroys,maps,unmaps,joins,world_destroys,valid_records,invalid_records,parks,returned_cleanup,stop_watermark,stop_before_publish);json_string(logs);puts("}");return 0;
}
