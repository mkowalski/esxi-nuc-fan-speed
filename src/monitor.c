/* SPDX-License-Identifier: BSD-2-Clause
 * Resident ESXi CPU-fan reader with bounded sampling and joined teardown.
 */
#define init_module static __attribute__((unused)) proof_init_module
#define cleanup_module static __attribute__((unused)) proof_cleanup_module
#include "fan_core.h"
#undef init_module
#undef cleanup_module

struct monitor_world_props {
    const char *name;
    int32_t module;
    uint32_t pad0;
    int32_t (*start)(void *);
    void *data;
    uint32_t sched_class,pad1;
    void *heap;
};
_Static_assert(sizeof(struct monitor_world_props)==48 &&
    offsetof(struct monitor_world_props,module)==8 &&
    offsetof(struct monitor_world_props,start)==16 &&
    offsetof(struct monitor_world_props,data)==24 &&
    offsetof(struct monitor_world_props,sched_class)==32 &&
    offsetof(struct monitor_world_props,heap)==40,"current world ABI");
extern int32_t vmk_WorldCreate(struct monitor_world_props *,uint32_t *);
extern uint64_t vmk_WorldCreateAllocSize(uint64_t *);
extern int32_t vmk_WorldSleep(uint64_t);
extern int32_t vmk_WorldDestroy(uint32_t);
extern int32_t vmk_WorldWaitForDeath(uint32_t);
extern void _vmk_LogMessage(const char *,...) __attribute__((format(printf,1,2)));

BSS static void *monitor_heap;
BSS static uint32_t monitor_world,world_accepted,init_pin,started,go,stop,terminal,publishing;
BSS static uint64_t sequence;
BSS static char world_name[32];
TEXT static int32_t monitor_loop(void *);
#ifdef __ELF__
__attribute__((section(".data")))
#endif
static struct monitor_world_props world_props={world_name,0,0,monitor_loop,NULL,1,0,NULL};
RO static const char record_format[]="nuc_fan_monitor: sample v=1 seq=%llu status=0x%x valid=%u rpm=%u reads=%u attempt=%u signature_ok=%u type=%u high=%u low=%u high_after=%u\n";
RO static const char lifecycle_format[]="nuc_fan_monitor: lifecycle stage=%u status=0x%x world=%u init_pin=%u\n";
RO static const char monitor_heap_name[]="nuc_fan_monitor";
RO static const char monitor_world_name[]="nuc_fan_poll";
RO static const char stopping_format[]="nuc_fan_monitor: stopping seq=%llu\n";

/* SC prevents stop/publication stores both remaining buffered while each
 * side observes the other's old zero. No IRQ spinlock is held over VMK calls. */
TEXT static uint32_t load_flag(uint32_t *p){return __atomic_load_n(p,__ATOMIC_SEQ_CST);}
TEXT static void store_flag(uint32_t *p,uint32_t value){__atomic_store_n(p,value,__ATOMIC_SEQ_CST);}
TEXT static uint64_t next_sequence(void){return __atomic_add_fetch(&sequence,1,__ATOMIC_RELAXED);}
TEXT static void invalid_record(int32_t status)
{
    _vmk_LogMessage(record_format,(unsigned long long)next_sequence(),(unsigned)(status?status:FAIL),
        0U,0U,0U,0U,0U,0U,0U,0U,0U);
}
TEXT static void emit_cycle(void)
{
    uint32_t valid=state.sample_valid && !state.status && state.safe;
    _vmk_LogMessage(record_format,(unsigned long long)next_sequence(),(unsigned)state.status,
        valid,valid?state.rpm:0,state.reads,state.attempt,state.signature_ok,
        (unsigned)state.type,(unsigned)state.high,(unsigned)state.low,(unsigned)state.high_after);
}
TEXT static void reset_cycle(void)
{
    volatile unsigned char *bytes=(volatile unsigned char *)&state;
    for(uint32_t i=0;i<sizeof(state);++i)bytes[i]=0;
    mapping.type=0;mapping.va=0;mapping.attrs=0;mapping.length=0;
    info.name=NULL;
}
TEXT static void cycle(void)
{
    uint32_t attempted=0;
    reset_cycle();
    if(!inventory()){
        int32_t status=vmk_ModuleIncUseCount(vmk_ModuleCurrentID);
        if(status)error(60,status);
        else {
            state.pinned=1;
            if(vmk_ModuleGetHeapID(vmk_ModuleCurrentID)!=monitor_heap || !state_guard() || !ledger_empty())error(61,FAIL);
            else {
                attempted=1;
                status=vmk_ACPIMapIOResource(vmk_ModuleCurrentID,state.target,4,&mapping);
                if(status)error(62,status);
                else {state.map_owned=1;if(!mapping_valid()||!state_guard())error(63,FAIL);else (void)sample();}
            }
        }
    }
    info.name=NULL;
    if(state.map_owned){
        int32_t status=vmk_ACPIUnmapIOResource(vmk_ModuleCurrentID,state.target,4);
        if(status){error(64,status);emit_cycle();return;}
        state.map_owned=0;mapping.type=0;mapping.va=0;
    }
    if(attempted && !ledger_empty()){error(65,FAIL);emit_cycle();return;}
    if(state.pinned){
        int32_t status=vmk_ModuleDecUseCount(vmk_ModuleCurrentID);
        if(status){error(66,status);emit_cycle();return;}
        state.pinned=0;
    }
    state.safe=1;emit_cycle();
}
TEXT static int32_t monitor_loop(void *unused)
{
    (void)unused;
    /* vmkWorldFunc frees the startup allocation before invoking this callback. */
    store_flag(&started,1);
    while(!load_flag(&go) && !load_flag(&stop)){
        int32_t status=vmk_WorldSleep(10000);
        if(status){invalid_record(status);store_flag(&terminal,1);return status;}
    }
    while(!load_flag(&stop)){
        store_flag(&publishing,1);
        if(load_flag(&stop)){store_flag(&publishing,0);break;}
        cycle();
        store_flag(&publishing,0);
        if(!state.safe){store_flag(&terminal,2);return state.status?state.status:FAIL;}
        if(load_flag(&stop))break;
        int32_t status=vmk_WorldSleep(30000000);
        if(load_flag(&stop))break;
        if(status){invalid_record(status);store_flag(&terminal,1);return status;}
    }
    store_flag(&terminal,1);
    return 0;
}
TEXT static int init_failure(uint32_t stage,int32_t status)
{
    store_flag(&stop,1);invalid_record(status);
    if(!world_accepted){
        if(monitor_heap){
            int32_t destroyed=vmk_HeapDestroySync(monitor_heap,1000);
            if(destroyed){_vmk_LogMessage(lifecycle_format,stage,(unsigned)destroyed,monitor_world,init_pin);return 0;}
            monitor_heap=NULL;
        }
        if(init_pin && !vmk_ModuleDecUseCount(vmk_ModuleCurrentID))init_pin=0;
    }
    _vmk_LogMessage(lifecycle_format,stage,(unsigned)status,monitor_world,init_pin);
    return 0; /* Retain any live startup ownership; no failed-init discard. */
}
TEXT int init_module(void)
{
    reset_cycle();
    if(inventory())return init_failure(1,state.status);
    int32_t status=vmk_ModuleIncUseCount(vmk_ModuleCurrentID);
    if(status)return init_failure(2,status);
    init_pin=1;
    if(vmk_ModuleGetHeapID(vmk_ModuleCurrentID))return init_failure(3,FAIL);
    status=vmk_NameInitialize(heap.name,monitor_heap_name);
    if(status)return init_failure(4,status);
    heap.type=0;heap.module=vmk_ModuleCurrentID;heap.initial=4096;heap.maximum=65536;heap.timeout=0;
    status=vmk_HeapCreate(&heap,&monitor_heap);
    if(status)return init_failure(5,status);
    if(!monitor_heap)return init_failure(5,FAIL);
    vmk_ModuleSetHeapID(vmk_ModuleCurrentID,monitor_heap);
    if(vmk_ModuleGetHeapID(vmk_ModuleCurrentID)!=monitor_heap)return init_failure(6,FAIL);
    uint64_t alignment=0;
    if(vmk_WorldCreateAllocSize(&alignment)!=11096 || alignment!=0)return init_failure(7,FAIL);
    status=vmk_NameInitialize(world_name,monitor_world_name);
    if(status)return init_failure(8,status);
    world_props.module=vmk_ModuleCurrentID;world_props.heap=monitor_heap;
    status=vmk_WorldCreate(&world_props,&monitor_world);
    if(status)return init_failure(9,status);
    world_accepted=1;
    if(!monitor_world)return init_failure(9,FAIL);
    for(uint32_t attempt=0;attempt<500 && !load_flag(&started);++attempt){
        status=vmk_WorldSleep(10000);
        if(status)return init_failure(10,status);
    }
    if(!load_flag(&started)||load_flag(&terminal))return init_failure(11,FAIL);
    status=vmk_ModuleDecUseCount(vmk_ModuleCurrentID);
    if(status)return init_failure(12,status);
    init_pin=0;
    store_flag(&go,1);
    _vmk_LogMessage(lifecycle_format,0,0U,monitor_world,init_pin);
    return 0;
}
TEXT static void park_cleanup(uint32_t stage,int32_t status)
{
    _vmk_LogMessage(lifecycle_format,stage,(unsigned)status,monitor_world,init_pin);
    for(;;)(void)vmk_WorldSleep(1000000); /* Keep cleanup/code resident; never return. */
}
TEXT void cleanup_module(void)
{
    store_flag(&stop,1);
    while(load_flag(&publishing))(void)vmk_WorldSleep(10000);
    _vmk_LogMessage(stopping_format,(unsigned long long)__atomic_load_n(&sequence,__ATOMIC_ACQUIRE));
    invalid_record(FAIL);
    if(monitor_world){
        (void)vmk_WorldDestroy(monitor_world);
        int32_t status;
        do {status=vmk_WorldWaitForDeath(monitor_world);} while(status);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        monitor_world=0;
    }
    invalid_record(FAIL);
    if(state.pinned || state.map_owned || init_pin)park_cleanup(20,FAIL);
    if(monitor_heap){
        int32_t status=vmk_HeapDestroySync(monitor_heap,1000);
        if(status)park_cleanup(21,status);
        monitor_heap=NULL;
    }
    _vmk_LogMessage(lifecycle_format,22,0U,monitor_world,init_pin);
}
