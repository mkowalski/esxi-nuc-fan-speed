/* Local fake kernel boundary. The real probe logic below is what is tested. */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "../../src/fan_core.h"

const int32_t vmk_ModuleCurrentID = 96;
static union { uint64_t align; unsigned char bytes[0x110]; } nodes[3];
static uint64_t ledger_storage[40];
static uint64_t *const ledger=ledger_storage+16; /* resource index4, stride32 */
static struct raw_resource raw[10];
static const char *scenario;
static unsigned iter_calls, maps, unmaps, reads, creates, destroys, pins, releases;
static int heap_live, associated, mapped_live, violation;
static char trace[256], logs[8192];
static size_t trace_len, log_len;
static uint64_t offsets[16];

static void event(char ch) { trace[trace_len++] = ch; trace[trace_len] = 0; }
static int is(const char *s) { return !strcmp(scenario, s); }
static void put64(unsigned n, unsigned off, uint64_t x) { memcpy(nodes[n].bytes+off,&x,8); }
static void put32(unsigned n, unsigned off, uint32_t x) { memcpy(nodes[n].bytes+off,&x,4); }
static uint64_t get64(unsigned n, unsigned off) { uint64_t x;memcpy(&x,nodes[n].bytes+off,8);return x; }
static int node_index(void *p) { for (int i=0;i<3;++i) if(p==nodes[i].bytes)return i;abort(); }
static void *const fake_heap = (void *)(uintptr_t)0x1000;

int32_t vmk_ACPIDeviceIterate(void *previous, void **out)
{
    ++iter_calls;
    if(is("iterate-error"))return 1;
    if(is("cap")){*out=nodes[0].bytes;return 0;}
    int i=previous==(void *)UINTPTR_MAX?-1:node_index(previous);
    *out=i<1?nodes[i+1].bytes:NULL;
    if(is("duplicate")&&i==1)*out=nodes[2].bytes;
    return 0;
}
int32_t vmk_ACPIQueryInfo(void *p, struct probe_info *out)
{
    int i=node_index(p);
    if(is("info-error"))return 1;
    out->count=10;out->irqs=0;out->name=(const char *)nodes[i].bytes+0xc8;
    if(is("count"))out->count=33;
    return 0;
}
int32_t vmk_ACPIQueryIOResources(void *p,uint32_t count,struct raw_resource *out)
{
    if(node_index(p)!=1||count!=10)abort();
    if(is("resources-error"))return 1;
    for(unsigned i=0;i<10;++i)out[i]=raw[i];
    return 0;
}
int32_t vmk_ModuleIncUseCount(int32_t id)
{
    if(id!=96)abort();event('P');if(is("pin-error"))return 1;++pins;return 0;
}
int32_t vmk_ModuleDecUseCount(int32_t id)
{
    if(id!=96||pins!=1||heap_live||mapped_live)abort();event('p');
    if(is("unpin-error"))return 1;--pins;++releases;return 0;
}
void *vmk_ModuleGetHeapID(int32_t id)
{
    if(id!=96)abort();if(is("old-heap"))return fake_heap;
    return associated&&!is("associate-error")?fake_heap:NULL;
}
void vmk_ModuleSetHeapID(int32_t id,void *heap)
{
    if(id!=96||heap!=fake_heap||!heap_live)abort();event('A');associated=1;
}
int32_t vmk_NameInitialize(char *name,const char *value)
{
    if(is("name-error"))return 1;strcpy(name,value);return 0;
}
int32_t vmk_HeapCreate(struct heap_props *props,void **out)
{
    event('H');++creates;
    if(!pins||props->type!=0||props->module!=96||props->initial!=4096||
       props->maximum!=65536||props->timeout!=0||strcmp(props->name,"nuc_fan_probe"))abort();
    if(is("heap-error"))return 1;heap_live=1;*out=fake_heap;return 0;
}
int32_t vmk_HeapDestroySync(void *heap,int64_t timeout)
{
    event('h');++destroys;
    if(heap!=fake_heap||!heap_live||mapped_live||!pins||timeout!=1000)abort();
    if(is("destroy-error"))return 1;heap_live=0;return 0;
}
int32_t vmk_ACPIMapIOResource(int32_t id,void *p,uint32_t index,struct mapped_resource *out)
{
    event('M');++maps;
    if(id!=96||node_index(p)!=1||index!=4||!heap_live||!pins||!associated)abort();
    if(is("map-error"))return 1;
    if(is("map-error-dirty")){ledger[1]=123;return 1;}
    ledger[1]=123;ledger[2]=UINT64_C(0x430010000000);mapped_live=1;
    out->type=is("port-type")?3:2;out->va=ledger[2];out->attrs=9;out->length=0x600000;
    if(is("attrs"))out->attrs=1;
    if(is("length"))out->length=0x200000;
    if(is("va-overflow"))out->va=UINT64_MAX-15;
    if(is("state-after-map"))put64(1,0x80,0x42);
    return 0;
}
int32_t vmk_ACPIUnmapIOResource(int32_t id,void *p,uint32_t index)
{
    event('U');++unmaps;
    if(id!=96||node_index(p)!=1||index!=4||!mapped_live||!heap_live||!pins)abort();
    if(is("unmap-error"))return 1;
    mapped_live=0;ledger[1]=ledger[2]=0;
    if(is("dirty-after-unmap"))ledger[1]=123;
    return 0;
}
int32_t vmk_MappedResourceRead8(const struct mapped_resource *m,uint64_t offset,uint8_t *out)
{
    if(!mapped_live||!heap_live||!pins||m->type!=2||m->attrs!=9||m->length!=0x600000||reads>=16)abort();
    if(!((offset>=0x210400&&offset<=0x210405)||(offset>=0x21041c&&offset<=0x21041e)))abort();
    event('R');offsets[reads++]=offset;
    if(is("read-error"))return 1;
    if(offset>=0x210400&&offset<=0x210405){*out=(unsigned char)"NUC_EC"[offset-0x210400];if(is("signature")&&offset==0x210400)*out='X';return 0;}
    if(offset==0x21041c){*out=is("fan-type")?2:1;return 0;}
    if(is("all-ones")){*out=255;return 0;}
    if(is("zero")){*out=0;return 0;}
    unsigned rpm_read=reads-8;
    if(is("unstable")){*out=(rpm_read%3==2)?8:7;return 0;}
    if(is("retry")&&rpm_read<3){*out=(rpm_read==2)?8:7;return 0;}
    *out=offset==0x21041d?7:0xb0;return 0; /* 1968 RPM */
}
void _vmk_WarningMessage(const char *format,...)
{
    va_list ap;va_start(ap,format);int n=vsnprintf(logs+log_len,sizeof(logs)-log_len,format,ap);va_end(ap);
    if(n<0||(size_t)n>=sizeof(logs)-log_len)abort();log_len+=(size_t)n;
}
static void json_string(const char *s)
{
    putchar('"');for(;*s;++s){if(*s=='"'||*s=='\\')putchar('\\');if(*s=='\n')fputs("\\n",stdout);else putchar(*s);}putchar('"');
}
int main(int argc,char **argv)
{
    if(argc!=2)return 2;scenario=argv[1];
    for(unsigned i=0;i<3;++i){put32(i,0,0x41435049);put32(i,0x68,10);put64(i,0x80,0x40);put64(i,0x38,(uintptr_t)ledger_storage);strcpy((char *)nodes[i].bytes+0xc8,i?"\\_SB_.PRRE":"\\_SB_.OTHER");}
    ledger[0]=0x100;
    for(unsigned i=0;i<10;++i){raw[i].kind=0;raw[i].base=0x1000+i*4096;raw[i].length=4096;}
    raw[4].base=0xfe200000;raw[4].length=0x600000;raw[4].flags=0;
    if(is("power"))put64(1,0x80,0x42);
    if(is("disabled"))put64(1,0x80,0x41);
    if(is("cache-error"))put64(1,0x80,0x44);
    if(is("unregistered"))put64(1,0x80,0);
    if(is("magic"))put32(1,0,0);
    if(is("busy"))ledger[1]=99;
    if(is("no-registration"))ledger[0]=0;
    if(is("null-ledger"))put64(1,0x38,0);
    if(is("table-overflow"))put64(1,0x38,UINT64_MAX-151);
    if(is("private-count"))put32(1,0x68,9);
    if(is("raw-kind"))raw[4].kind=1;
    if(is("raw-flags"))raw[4].flags=1;
    if(is("range"))raw[4].base++;
    if(is("prefix"))strcpy((char *)nodes[1].bytes+0xc8,"\\_SB_.PRREX");
    if(is("null-name"))nodes[1].bytes[0xc8]=0;
    int status=init_module();
    if(!pins)cleanup_module();
    printf("{\"loader_status\":%d,\"maps\":%u,\"unmaps\":%u,\"reads\":%u,\"heap_live\":%d,\"pins\":%u,\"destroys\":%u,\"creates\":%u,\"iter_calls\":%u,\"trace\":",status,maps,unmaps,reads,heap_live,pins,destroys,creates,iter_calls);
    json_string(trace);fputs(",\"log\":",stdout);json_string(logs);fputs(",\"offsets\":[",stdout);
    for(unsigned i=0;i<reads;++i)printf("%s%llu",i?",":"",(unsigned long long)offsets[i]);puts("]}");
    return violation||get64(0,0x80)!=0x40;
}
