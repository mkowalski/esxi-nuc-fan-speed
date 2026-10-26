/* SPDX-License-Identifier: BSD-2-Clause
 * Exact-build ESXi fan acquisition core. No writes to mapped hardware.
 * Private cache offsets are pinned to kernel SHA256 3c55688c...9ac52;
 * the operator MUST verify that image/build and preventFreePageMapping=FALSE.
 * Stable host/no concurrent PRRE mapping or lifecycle operation is required.
 */
#include <stdint.h>
#include <stddef.h>

struct probe_info { uint32_t count, irqs; const char *name; };
struct raw_resource { uint32_t kind, padding; uint64_t base, length, flags; };
struct mapped_resource { uint32_t type, padding; uint64_t va, attrs, length; };
struct heap_props {
    uint32_t type;
    char name[32];
    int32_t module;
    uint32_t initial, maximum, timeout, padding;
    uint64_t unused_union[2];
};
_Static_assert(sizeof(void *)==8,"64-bit target");
_Static_assert(sizeof(struct probe_info)==16 && offsetof(struct probe_info,name)==8,"query ABI");
_Static_assert(sizeof(struct raw_resource)==32 && offsetof(struct raw_resource,base)==8 &&
               offsetof(struct raw_resource,length)==16 && offsetof(struct raw_resource,flags)==24,"raw ABI");
_Static_assert(sizeof(struct mapped_resource)==32 && offsetof(struct mapped_resource,va)==8 &&
               offsetof(struct mapped_resource,attrs)==16 && offsetof(struct mapped_resource,length)==24,"mapped ABI");
_Static_assert(sizeof(struct heap_props)==72 && offsetof(struct heap_props,name)==4 &&
               offsetof(struct heap_props,module)==36 && offsetof(struct heap_props,initial)==40 &&
               offsetof(struct heap_props,maximum)==44 && offsetof(struct heap_props,timeout)==48 &&
               offsetof(struct heap_props,unused_union)==56,"legacy heap ABI");

extern const int32_t vmk_ModuleCurrentID;
extern int32_t vmk_ACPIDeviceIterate(void *,void **);
extern int32_t vmk_ACPIQueryInfo(void *,struct probe_info *);
extern int32_t vmk_ACPIQueryIOResources(void *,uint32_t,struct raw_resource *);
extern int32_t vmk_ModuleIncUseCount(int32_t);
extern int32_t vmk_ModuleDecUseCount(int32_t);
extern void *vmk_ModuleGetHeapID(int32_t);
extern void vmk_ModuleSetHeapID(int32_t,void *);
extern int32_t vmk_NameInitialize(char *,const char *);
extern int32_t vmk_HeapCreate(struct heap_props *,void **);
extern int32_t vmk_HeapDestroySync(void *,int64_t);
extern int32_t vmk_ACPIMapIOResource(int32_t,void *,uint32_t,struct mapped_resource *);
extern int32_t vmk_ACPIUnmapIOResource(int32_t,void *,uint32_t);
extern int32_t vmk_MappedResourceRead8(const struct mapped_resource *,uint64_t,uint8_t *);
extern void _vmk_WarningMessage(const char *,...) __attribute__((format(printf,1,2)));

#define FAIL ((int32_t)0x0bad0001)
#ifdef __ELF__
#define RO __attribute__((section(".rodata"),used,aligned(1)))
#define TEXT __attribute__((section(".text")))
#define BSS __attribute__((section(".bss")))
#else
#define RO __attribute__((used,aligned(1)))
#define TEXT
#define BSS
#endif
RO static const char path[]="\\_SB_.PRRE";
RO static const char signature[]="NUC_EC";
RO static const char heap_name[]="nuc_fan_probe";
RO static const char start_format[]="nuc_fan_proof: init module=%d bounded-read-only-operations whole-resource-writable-map\n";
RO static const char result_format[]="nuc_fan_proof: result status=0x%x stage=%u valid=%u rpm=%u reads=%u attempt=%u flags=0x%llx safe_to_unload=%u pinned=%u heap_owned=%u map_owned=%u\n";
RO static const char cleanup_format[]="nuc_fan_proof: cleanup module=%d safe_to_unload=%u\n";
RO static const char bytes_format[]="nuc_fan_proof: sample signature_ok=%u type=%u high=%u low=%u high_after=%u; high-byte stability is not atomic publication\n";

BSS static struct {
    void *target, *heap;
    volatile uint64_t *entry;
    uint64_t flags, registration;
    uint32_t pinned, heap_owned, map_owned, safe, stage;
    uint32_t visited, matches, reads, attempt, sample_valid, rpm, signature_ok;
    uint8_t type, high, low, high_after;
    int32_t status;
} state;
BSS static struct probe_info info;
BSS static struct raw_resource resources[32];
BSS static struct mapped_resource mapping;
BSS static struct heap_props heap;

TEXT static int32_t error(uint32_t stage,int32_t status)
{
    state.stage=stage;
    state.status=status?status:FAIL;
    return state.status;
}
TEXT static int target_name(const char *name)
{
    if(!name)return 0;
    const volatile unsigned char *s=(const volatile unsigned char *)name;
    uint32_t match=1;
    for(uint32_t i=0;i<64;++i){
        unsigned char ch=s[i];
        if(i>=sizeof(path)||ch!=(unsigned char)path[i])match=0;
        if(!ch)return match && i==sizeof(path)-1;
    }
    return 0;
}
TEXT static uint64_t private64(uint32_t offset)
{
    return *(const volatile uint64_t *)((const unsigned char *)state.target+offset);
}
TEXT static uint32_t private32(uint32_t offset)
{
    return *(const volatile uint32_t *)((const unsigned char *)state.target+offset);
}
TEXT static int state_guard(void)
{
    if(private32(0)!=0x41435049 || private32(0x68)!=10)return 0;
    uint64_t flags=private64(0x80);
    if(!(flags&0x40) || (flags&0x87))return 0;
    return !state.entry || (flags==state.flags &&
        private64(0x38)+(uint64_t)4*32==(uintptr_t)state.entry);
}
TEXT static int ledger_empty(void)
{
    return state.entry && private64(0x38)+(uint64_t)4*32==(uintptr_t)state.entry &&
        state.entry[0]==state.registration && !state.entry[1] &&
        !state.entry[2] && !state.entry[3];
}
TEXT static int32_t inventory(void)
{
    void *cursor=(void *)UINTPTR_MAX;
    uint32_t ended=0;
    for(uint32_t step=0;step<1024;++step){
        void *next=NULL;
        int32_t status=vmk_ACPIDeviceIterate(cursor,&next);
        if(status)return error(1,status);
        if(!next){ended=1;break;}
        cursor=next;++state.visited;
        status=vmk_ACPIQueryInfo(cursor,&info);
        if(status)return error(2,status);
        if(target_name(info.name)){
            if(++state.matches!=1)return error(3,FAIL);
            if(info.count!=10)return error(4,FAIL);
            state.target=cursor;
        }
    }
    info.name=NULL;
    if(!ended || state.matches!=1)return error(5,FAIL);
    int32_t status=vmk_ACPIQueryInfo(state.target,&info);
    if(status || info.count!=10 || !target_name(info.name))return error(6,status);
    const char *name=info.name;
    status=vmk_ACPIQueryIOResources(state.target,10,resources);
    if(status)return error(7,status);
    status=vmk_ACPIQueryInfo(state.target,&info);
    if(status || info.count!=10 || info.name!=name)return error(8,status);
    info.name=NULL;
    uint32_t matches=0;
    for(uint32_t i=0;i<10;++i){
        if(resources[i].base==UINT64_C(0xfe200000) && resources[i].length==0x600000){
            ++matches;
            if(i!=4 || resources[i].kind!=0 || resources[i].flags!=0)return error(9,FAIL);
        }
    }
    if(matches!=1 || !state_guard())return error(10,FAIL);
    state.flags=private64(0x80);
    uint64_t table=private64(0x38);
    if(!table || (table&7) || table>UINT64_MAX-(4+1)*32)return error(11,FAIL);
    state.entry=(volatile uint64_t *)(uintptr_t)(table+4*32);
    state.registration=state.entry[0];
    if(!state.registration || !ledger_empty())return error(12,FAIL);
    return 0;
}
TEXT static int mapping_valid(void)
{
    return mapping.type==2 && mapping.attrs==9 && mapping.length==0x600000 &&
        !(mapping.va&0xfff) && mapping.va>=UINT64_C(0x430000000000) &&
        mapping.va<=UINT64_C(0x800000000000)-UINT64_C(0x600000);
}
TEXT static int32_t read_byte(uint64_t offset,uint8_t *out)
{
    if(!state.map_owned || !mapping_valid() || state.reads>=16 ||
       !((offset>=0x210400 && offset<=0x210405) ||
         (offset>=0x21041c && offset<=0x21041e)) ||
       offset>=mapping.length || mapping.va>UINT64_MAX-offset)
        return error(20,FAIL);
    ++state.reads;
    int32_t status=vmk_MappedResourceRead8(&mapping,offset,out);
    return status?error(21,status):0;
}
TEXT static int32_t sample(void)
{
    for(uint32_t i=0;i<6;++i){
        uint8_t byte=0;
        int32_t status=read_byte(0x210400+i,&byte);
        if(status)return status;
        if(byte!=(uint8_t)signature[i])return error(22,FAIL);
    }
    state.signature_ok=1;
    int32_t status=read_byte(0x21041c,&state.type);
    if(status)return status;
    if(state.type!=1)return error(23,FAIL);
    for(uint32_t i=0;i<3;++i){
        state.attempt=i+1;
        status=read_byte(0x21041d,&state.high);if(status)return status;
        status=read_byte(0x21041e,&state.low);if(status)return status;
        status=read_byte(0x21041d,&state.high_after);if(status)return status;
        if(state.high!=state.high_after)continue;
        state.rpm=((uint32_t)state.high<<8)|state.low;
        if(state.rpm==65535)return error(24,FAIL);
        state.sample_valid=1;
        return 0;
    }
    return error(25,FAIL);
}
TEXT static int32_t acquire_and_sample(void)
{
    int32_t status=vmk_ModuleIncUseCount(vmk_ModuleCurrentID);
    if(status)return error(30,status);
    state.pinned=1;
    if(vmk_ModuleGetHeapID(vmk_ModuleCurrentID))return error(31,FAIL);
    status=vmk_NameInitialize(heap.name,heap_name);
    if(status)return error(32,status);
    heap.type=0;heap.module=vmk_ModuleCurrentID;heap.initial=4096;
    heap.maximum=65536;heap.timeout=0;
    status=vmk_HeapCreate(&heap,&state.heap);
    if(status)return error(33,status);
    if(!state.heap)return error(34,FAIL);
    state.heap_owned=1;
    vmk_ModuleSetHeapID(vmk_ModuleCurrentID,state.heap);
    if(vmk_ModuleGetHeapID(vmk_ModuleCurrentID)!=state.heap)return error(35,FAIL);
    if(!state_guard() || !ledger_empty())return error(36,FAIL);
    status=vmk_ACPIMapIOResource(vmk_ModuleCurrentID,state.target,4,&mapping);
    if(status)return error(37,status);
    state.map_owned=1; /* Set BEFORE any validation that can fail. */
    if(!mapping_valid() || !state_guard())return error(38,FAIL);
    return sample();
}
TEXT static void release_owned(void)
{
    if(state.map_owned){
        int32_t status=vmk_ACPIUnmapIOResource(vmk_ModuleCurrentID,state.target,4);
        if(status){error(40,status);return;}
        state.map_owned=0;
        mapping.type=0;mapping.va=0;
    }
    /* Failed Map can still leave unexpected shared state. Never guess ownership. */
    if(state.heap_owned && !ledger_empty()){error(41,FAIL);return;}
    if(state.heap_owned){
        int32_t status=vmk_HeapDestroySync(state.heap,1000);
        if(status){error(42,status);return;}
        state.heap_owned=0;state.heap=NULL;
    }
    if(state.pinned){
        int32_t status=vmk_ModuleDecUseCount(vmk_ModuleCurrentID);
        if(status){error(43,status);return;}
        state.pinned=0;
    }
    state.safe=1;
}

#ifdef __ELF__
__attribute__((section(".vmkmodinfo"),used,aligned(1)))
static const char __vmk_licenseInfo_str[]="license=BSD";
__attribute__((section(".vmkmodinfo"),used,aligned(1)))
static const char __vmk_buildTypeInfo_str[]="buildType=release";
__attribute__((section(".vmkmodinfo"),used,aligned(1)))
static const char __vmk_versionInfo_str[]="version=0.0.1-fan-proof";
__attribute__((section(".vmkmodinfo"),used,aligned(1)))
static const char __vmk_nsRequiredInfo_str[]="nsRequired=com.vmware.vmkapi#v2_13_0_0";
__attribute__((section(".vmkrequiredns"),used,aligned(1)))
static const char namespace_required[]="com.vmware.vmkapi#v2_13_0_0";
#endif

TEXT int init_module(void)
{
    _vmk_WarningMessage(start_format,vmk_ModuleCurrentID);
    state.status=0;
    if(!inventory())(void)acquire_and_sample();
    info.name=NULL;
    release_owned();
    uint32_t valid=state.sample_valid && state.status==0 && state.safe;
    _vmk_WarningMessage(bytes_format,state.signature_ok,(unsigned)state.type,
        (unsigned)state.high,(unsigned)state.low,(unsigned)state.high_after);
    _vmk_WarningMessage(result_format,(unsigned)state.status,state.stage,valid,
        valid?state.rpm:0,state.reads,state.attempt,(unsigned long long)state.flags,
        state.safe,state.pinned,state.heap_owned,state.map_owned);
    /* Live ownership MUST remain resident on diagnostic/cleanup failure. */
    return 0;
}
TEXT void cleanup_module(void)
{
    _vmk_WarningMessage(cleanup_format,vmk_ModuleCurrentID,state.safe);
}
