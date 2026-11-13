#include <nlohmann/json.hpp>
#include <atomic>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <string>
#include <link.h>
#include <dlfcn.h>

using Json=nlohmann::json;
struct NameEntry{uint8_t reserved[12];char name[64];};
struct Object{void* vtable;uint32_t flags;int32_t index;Object* cls;uint32_t name,number;Object* outer;};
struct Params{uint64_t count;bool nested;};
static NameEntry entries[8]{};
static NameEntry* chunk[16384]{};
static NameEntry** chunks[1]={chunk};
extern "C" __attribute__((visibility("default"))) NameEntry*** fixture_names=chunks;
static Object packageObject{},classObject{},rootFunction{},nestedFunction{},testObject{};
static std::atomic<uint64_t> calls{0};

extern "C" __attribute__((visibility("default"),noinline)) void FixtureProcessEvent(void* object,void* function,void* parameter){
    asm volatile("nop\nnop\nnop\nnop":::"memory");
    auto* p=static_cast<Params*>(parameter);p->count++;calls.fetch_add(1);
    if(function==&rootFunction&&!p->nested){p->nested=true;void(*volatile target)(void*,void*,void*)=&FixtureProcessEvent;target(object,&nestedFunction,parameter);p->nested=false;}
}
static std::string hex(uintptr_t x){char b[32];snprintf(b,sizeof b,"0x%llx",static_cast<unsigned long long>(x));return b;}
static std::string bytes(const void* ptr,size_t n){std::string s;const uint8_t* b=static_cast<const uint8_t*>(ptr);char h[3];for(size_t i=0;i<n;++i){snprintf(h,sizeof h,"%02x",b[i]);s+=h;}return s;}
extern "C" __attribute__((visibility("default"))) const char* FixtureProfile(const char* process){
    const char* names[]={"None","Fixture","ObjectClass","RootEvent","NestedEvent","TestObject"};
    for(int i=0;i<6;++i){uint32_t header=uint32_t(i)<<1;memcpy(entries[i].reserved+8,&header,sizeof(header));snprintf(entries[i].name,sizeof entries[i].name,"%s",names[i]);chunk[i]=&entries[i];}
    packageObject.name=1;classObject.name=2;classObject.outer=&packageObject;classObject.cls=&classObject;
    rootFunction.name=3;rootFunction.outer=&packageObject;rootFunction.cls=&classObject;
    nestedFunction.name=4;nestedFunction.outer=&packageObject;nestedFunction.cls=&classObject;
    testObject.name=5;testObject.outer=&packageObject;testObject.cls=&classObject;
    Dl_info di{};dladdr(reinterpret_cast<void*>(&FixtureProcessEvent),&di);uintptr_t base=reinterpret_cast<uintptr_t>(di.dli_fbase);
    std::pair<uintptr_t,std::string> info{base,{}};
    dl_iterate_phdr([](dl_phdr_info* d,size_t,void* ptr){auto& x=*static_cast<std::pair<uintptr_t,std::string>*>(ptr);if(d->dlpi_addr!=x.first)return 0;for(int i=0;i<d->dlpi_phnum;++i){auto& p=d->dlpi_phdr[i];if(p.p_type!=PT_NOTE)continue;auto* b=reinterpret_cast<const uint8_t*>(d->dlpi_addr+p.p_vaddr);for(size_t off=0;off+12<=p.p_memsz;){Elf64_Nhdr h;memcpy(&h,b+off,12);off+=12;size_t n=(h.n_namesz+3)&~size_t(3),v=(h.n_descsz+3)&~size_t(3);if(n+v>p.p_memsz-off)break;if(h.n_type==NT_GNU_BUILD_ID&&h.n_namesz==4&&memcmp(b+off,"GNU",4)==0)x.second=bytes(b+off+n,h.n_descsz);off+=n+v;}}return 1;},&info);
    Json p={{"schema_version",1},{"package",process},{"version_name","fixture"},{"version_code",1},{"abi","arm64-v8a"},{"module","libue4trace_fixture_module.so"},{"build_id",info.second},{"sha256","fixture-runtime-identity"},
      {"offsets",{{"process_event",hex(reinterpret_cast<uintptr_t>(&FixtureProcessEvent)-base)},{"gnames",hex(reinterpret_cast<uintptr_t>(&fixture_names)-base)},{"gobjects","0x0"},{"gactivity","0x0"}}},
      {"layout",{{"name_kind","legacy"},{"names_indirect",1},{"chunk_size",16384},{"name_entry_string",12},{"object_name",24},{"object_class",16},{"object_outer",32},{"function_flags",136}}},
      {"process_event_prologue",bytes(reinterpret_cast<void*>(&FixtureProcessEvent),16)}};
    static std::string result;result=p.dump(2);return result.c_str();
}
extern "C" __attribute__((visibility("default"))) int FixtureTick(){Params p{0,false};void(*volatile target)(void*,void*,void*)=&FixtureProcessEvent;target(&testObject,&rootFunction,&p);return p.count==2?0:1;}
extern "C" __attribute__((visibility("default"))) uint64_t FixtureCount(){return calls.load();}
