#include "ProcessEventTracer.h"
#include "dobby.h"
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <link.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <android/log.h>
#include <thread>
#include <limits>

namespace {
using Json=nlohmann::json;
#ifndef UE4TRACE_BUILD_SHA
#define UE4TRACE_BUILD_SHA "unversioned"
#endif
#ifndef UE4TRACE_AGENT_VERSION
#define UE4TRACE_AGENT_VERSION "0.1.0"
#endif
thread_local bool agentThread=false;
thread_local uint64_t currentCall=0;
thread_local uint32_t currentDepth=0;
thread_local uint32_t cachedTid=0;
constexpr uintptr_t PointerMask=0x00ffffffffffffffULL;
uint64_t NowUs() { timespec t{}; clock_gettime(CLOCK_MONOTONIC,&t); return uint64_t(t.tv_sec)*1000000+t.tv_nsec/1000; }
std::string Hex(uintptr_t n) { char b[32]; snprintf(b,sizeof b,"0x%llx",static_cast<unsigned long long>(n)); return b; }
std::string BytesHex(const void* data,size_t size) { const auto* p=static_cast<const uint8_t*>(data); std::string out; out.reserve(size*2); constexpr char h[]="0123456789abcdef"; for(size_t i=0;i<size;++i){out+=h[p[i]>>4];out+=h[p[i]&15];} return out; }
uintptr_t Number(const Json& j) {
    if(j.is_number_unsigned()) return j.get<uintptr_t>();
    if(j.is_number_integer()&&j.get<int64_t>()>=0) return j.get<uintptr_t>();
    if(!j.is_string()) throw std::runtime_error("address must be a hex string or unsigned integer");
    auto s=j.get<std::string>(); if(s.empty()||s.size()>18||s[0]=='-') throw std::runtime_error("invalid address");
    size_t pos=0; auto value=std::stoull(s,&pos,0); if(pos!=s.size())throw std::runtime_error("invalid address suffix"); return value;
}
bool Fits(uintptr_t a,size_t n){return a>=4096 && a<0x0001000000000000ULL && n<=0x100000 && a<=UINTPTR_MAX-n;}
std::string ProcessName(){char b[256]{}; int f=open("/proc/self/cmdline",O_RDONLY|O_CLOEXEC);if(f<0)return {};ssize_t n=read(f,b,sizeof(b)-1);close(f);return n>0?std::string(b,strnlen(b,size_t(n))):std::string();}
std::string Basename(std::string s){auto p=s.find_last_of('/');return p==std::string::npos?s:s.substr(p+1);}
std::string Lower(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(std::tolower(c));});return s;}
struct ModuleInfo { std::string name; uintptr_t base=0,end=0; std::vector<Elf64_Phdr> phdrs; std::vector<std::pair<uintptr_t,uintptr_t>> executable; };
struct OwnedSocket {
    int fd;
    explicit OwnedSocket(int value):fd(value){}
    ~OwnedSocket(){if(fd>=0)close(fd);}
    OwnedSocket(const OwnedSocket&)=delete;
    OwnedSocket& operator=(const OwnedSocket&)=delete;
};
int PageProtection(uintptr_t address,size_t size){
    FILE* f=fopen("/proc/self/maps","r");if(!f)return -1;
    char line[1024],perms[5];unsigned long start=0,end=0;int result=-1;
    while(fgets(line,sizeof line,f))if(sscanf(line,"%lx-%lx %4s",&start,&end,perms)==3&&address>=start&&address<end&&size<=end-address){result=(perms[0]=='r'?PROT_READ:0)|(perms[1]=='w'?PROT_WRITE:0)|(perms[2]=='x'?PROT_EXEC:0);break;}
    fclose(f);return result;
}
struct CodeWriteGuard {
    void* page;size_t size;int original;bool active=false;
    CodeWriteGuard(void* p,size_t n,int protection):page(p),size(n),original(protection){}
    bool Enable(){active=mprotect(page,size,PROT_READ|PROT_WRITE|PROT_EXEC)==0;return active;}
    bool Restore(){if(!active)return true;if(mprotect(page,size,original)!=0)return false;active=false;return true;}
    ~CodeWriteGuard(){if(!Restore())__android_log_print(ANDROID_LOG_ERROR,"UE4Trace","Cannot restore code-page permissions; target restart required");}
};
int FindModule(dl_phdr_info* info,size_t,void* opaque){
    auto& m=*static_cast<ModuleInfo*>(opaque);
    if(Basename(info->dlpi_name?info->dlpi_name:"")!=m.name)return 0;
    m.base=info->dlpi_addr;
    for(size_t i=0;i<info->dlpi_phnum;++i){const auto& p=info->dlpi_phdr[i];m.phdrs.push_back(p);if(p.p_type==PT_LOAD){m.end=std::max<uintptr_t>(m.end,m.base+p.p_vaddr+p.p_memsz);if(p.p_flags&PF_X)m.executable.emplace_back(m.base+p.p_vaddr,m.base+p.p_vaddr+p.p_memsz);}}
    return 1;
}
}

static_assert(std::atomic<uint64_t>::is_always_lock_free,"Hook counters must be lock free");
ProcessEventTracer::ProcessEventTracer(){memoryFd_=open("/proc/self/mem",O_RDONLY|O_CLOEXEC);}
ProcessEventTracer& ProcessEventTracer::Instance(){static auto* p=new ProcessEventTracer;return *p;}
bool ProcessEventTracer::Read(uintptr_t a,void* d,size_t n)const{
    a&=PointerMask;if(memoryFd_<0||!Fits(a,n))return false;
    ssize_t got=pread64(memoryFd_,d,n,static_cast<off64_t>(a));return got==static_cast<ssize_t>(n);
}
uintptr_t ProcessEventTracer::Pointer(uintptr_t a)const{uintptr_t v=0;return Read(a,&v,sizeof v)?v&PointerMask:0;}
std::string ProcessEventTracer::CString(uintptr_t a,size_t cap)const{
    std::string s; s.reserve(64);a&=PointerMask;
    for(size_t off=0;off<cap;){char b[64];size_t n=std::min<size_t>({sizeof b,cap-off,4096-((a+off)&4095)});if(!Read(a+off,b,n))return {};for(size_t i=0;i<n;++i){if(!b[i])return s;s+=b[i];}off+=n;}
    return {}; // Never represent an unterminated arbitrary region as a name.
}
std::string ProcessEventTracer::Name(uint32_t id){
    auto found=nameCache_.find(id);if(found!=nameCache_.end())return found->second;
    if(id>0x3fffffff)return "<invalid-name>";
    uintptr_t p=names_;for(uint32_t i=0;i<layout_.indirect;++i)p=Pointer(p);
    std::string result;
    if(layout_.kind=="legacy"){
        uintptr_t chunk=Pointer(p+(id/layout_.chunkSize)*8ULL);
        uintptr_t entry=Pointer(chunk+(id%layout_.chunkSize)*8ULL);
        uint32_t header=0;
        if(layout_.legacyHeaderCheck&&(!Read(entry+layout_.entryHeader,&header,sizeof header)||(header>>1)!=id))return "<invalid-name-header>";
        if(layout_.legacyHeaderCheck&&(header&1))return "<wide-name-not-decoded>";
        result=CString(entry+layout_.entryString,512);
    }else{
        uint32_t block=id>>layout_.poolBlockBits,offset=id&((1u<<layout_.poolBlockBits)-1);
        if(block>=8192)return "<invalid-name>";
        uintptr_t chunk=Pointer(p+layout_.poolBlocks+block*8ULL),entry=chunk+offset*2ULL;
        uint16_t header=0;if(!Read(entry,&header,2))return "<unreadable-name>";
        uint32_t length=header>>layout_.poolLengthShift;if(!length||length>511)return "<invalid-name>";
        if(header&1){std::vector<uint16_t> w(length);if(!Read(entry+2,w.data(),length*2))return "<unreadable-name>";
            for(size_t i=0;i<w.size();++i){uint32_t c=w[i];if(c>=0xd800&&c<=0xdbff&&i+1<w.size()&&w[i+1]>=0xdc00&&w[i+1]<=0xdfff){c=0x10000+((c-0xd800)<<10)+(w[++i]-0xdc00);}else if(c>=0xd800&&c<=0xdfff)c=0xfffd;
                if(c<128)result+=char(c);else if(c<2048){result+=char(0xc0|(c>>6));result+=char(0x80|(c&63));}else if(c<65536){result+=char(0xe0|(c>>12));result+=char(0x80|((c>>6)&63));result+=char(0x80|(c&63));}else{result+=char(0xf0|(c>>18));result+=char(0x80|((c>>12)&63));result+=char(0x80|((c>>6)&63));result+=char(0x80|(c&63));}}
        }else{result.resize(length);if(!Read(entry+2,result.data(),length))return "<unreadable-name>";}
    }
    if(result.empty())return "<unreadable-name>";
    if(nameCache_.size()>65536)nameCache_.clear();
    nameCache_[id]=result;return result;
}
std::string ProcessEventTracer::ObjectName(uintptr_t object,bool path){
    object&=PointerMask;if(!object)return "<null>";
    std::array<uintptr_t,32> visited{};std::vector<std::string> parts;
    for(size_t depth=0;object&&depth<visited.size();++depth){
        if(std::find(visited.begin(),visited.begin()+depth,object)!=visited.begin()+depth){parts.push_back("<cycle>");break;}
        visited[depth]=object;uint32_t fname[2]{};
        if(!Read(object+layout_.objectName,fname,sizeof fname)){parts.push_back("<expired>"+Hex(object));break;}
        auto s=Name(fname[0]);if(fname[1])s+="_"+std::to_string(fname[1]-1);parts.push_back(s);
        if(!path)break;object=Pointer(object+layout_.objectOuter);
    }
    std::string out;for(auto i=parts.rbegin();i!=parts.rend();++i){if(!out.empty())out+='.';out+=*i;}
    return out;
}
bool ProcessEventTracer::Push(const Record&r){
    if(queueLock_.test_and_set(std::memory_order_acquire))return false;
    bool ok=queued_.load(std::memory_order_relaxed)<Capacity;
    if(ok){queue_[writeIndex_]=r;writeIndex_=(writeIndex_+1)%Capacity;queued_.fetch_add(1,std::memory_order_relaxed);}
    queueLock_.clear(std::memory_order_release);return ok;
}
bool ProcessEventTracer::Pop(Record&r){
    if(queueLock_.test_and_set(std::memory_order_acquire))return false;
    bool ok=queued_.load(std::memory_order_relaxed)>0;
    if(ok){r=queue_[readIndex_];readIndex_=(readIndex_+1)%Capacity;queued_.fetch_sub(1,std::memory_order_relaxed);}
    queueLock_.clear(std::memory_order_release);return ok;
}
void ProcessEventTracer::ClearQueue(){Record r{};while(Pop(r)){};}
void ProcessEventTracer::Hook(void* object,void* function,void* parameters){
    auto& self=Instance();
    // Dobby writes the trampoline output before publishing the entry patch.
    ProcessEvent original=__atomic_load_n(&self.original_,__ATOMIC_ACQUIRE);
    if(agentThread||!self.recording_.load(std::memory_order_acquire)){original(object,function,parameters);return;}
    const auto started=NowUs(),epoch=self.epoch_.load(std::memory_order_relaxed);
    const auto id=self.calls_.fetch_add(1,std::memory_order_relaxed)+1;
    const auto parent=currentCall;const auto depth=currentDepth++;
    currentCall=id;if(!cachedTid)cachedTid=uint32_t(syscall(SYS_gettid));
    self.seen_.fetch_add(1,std::memory_order_relaxed);
    uintptr_t caller=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    // A scope guard preserves nested linkage even if the original propagates an exception.
    struct Scope {
        ProcessEventTracer& tracer;Record record;uint64_t prior;
        ~Scope(){
            currentCall=prior;--currentDepth;
            if(!tracer.recording_.load(std::memory_order_acquire)||record.epoch!=tracer.epoch_.load(std::memory_order_relaxed))return;
            record.duration=NowUs()-record.started;
            uint64_t next=tracer.nextAdmissionUs_.load(std::memory_order_relaxed),second=NowUs()/1000000;
            uint32_t rate=tracer.maxRate_.load(std::memory_order_relaxed);
            // A bounded burst budget preserves adjacent nested calls. Contention drops.
            uint64_t used=(next>>20)==second?(next&0xfffff):0,replacement=(second<<20)|(used+1);
            if(used>=rate||!tracer.nextAdmissionUs_.compare_exchange_strong(next,replacement,std::memory_order_relaxed)||!tracer.Push(record))tracer.dropped_.fetch_add(1,std::memory_order_relaxed);
        }
    } scope{self,{id,parent,started,0,epoch,reinterpret_cast<uintptr_t>(object),reinterpret_cast<uintptr_t>(function),caller,cachedTid,depth},parent};
    original(object,function,parameters); // Exactly one original call; arguments remain unchanged.
}
bool ProcessEventTracer::IsExecutable(uintptr_t address,size_t n)const{for(auto r:executableRanges_)if(address>=r.first&&address<=r.second&&n<=r.second-address)return true;return false;}
bool ProcessEventTracer::Configure(const Json& p,std::string& error){
    try{
        if(installed_.load()){if(p.dump()!=profileIdentity_){error="A different hook is already installed; restart the target before changing profile";return false;}return true;}
        if(hookAttempted_)throw std::runtime_error("Previous hook installation failed; restart the target before retrying");
        if(memoryFd_<0)throw std::runtime_error("Cannot read /proc/self/mem");
        if(p.at("schema_version")!=1||p.at("abi")!="arm64-v8a")throw std::runtime_error("Unsupported profile schema/ABI");
        package_=p.at("package").get<std::string>();if(ProcessName()!=package_)throw std::runtime_error("Profile package differs from target process");
        module_=p.at("module").get<std::string>();if(module_.empty()||module_.find('/')!=std::string::npos)throw std::runtime_error("Expected module basename");
        ModuleInfo m;m.name=module_;dl_iterate_phdr(FindModule,&m);if(!m.base||m.end<=m.base)throw std::runtime_error("Target module is not loaded");
        base_=m.base;moduleEnd_=m.end;executableRanges_=m.executable;buildId_.clear();
        for(const auto& ph:m.phdrs)if(ph.p_type==PT_NOTE&&ph.p_memsz<=1024*1024){std::vector<uint8_t> notes(ph.p_memsz);if(!Read(base_+ph.p_vaddr,notes.data(),notes.size()))continue;
            for(size_t off=0;off+sizeof(Elf64_Nhdr)<=notes.size();){Elf64_Nhdr nh;memcpy(&nh,notes.data()+off,sizeof nh);off+=sizeof nh;size_t ns=(size_t(nh.n_namesz)+3)&~size_t(3),ds=(size_t(nh.n_descsz)+3)&~size_t(3);if(ns>notes.size()-off||ds>notes.size()-off-ns)break;if(nh.n_type==NT_GNU_BUILD_ID&&nh.n_namesz==4&&memcmp(notes.data()+off,"GNU",4)==0)buildId_=BytesHex(notes.data()+off+ns,nh.n_descsz);off+=ns+ds;}}
        auto expected=Lower(p.at("build_id").get<std::string>());if(expected.empty()||buildId_!=expected)throw std::runtime_error("ELF build-id mismatch");
        uintptr_t rva=Number(p.at("offsets").at("process_event")),gn=Number(p.at("offsets").at("gnames"));
        if(rva>=moduleEnd_-base_||gn>=moduleEnd_-base_)throw std::runtime_error("Offset outside module");
        target_=base_+rva;names_=base_+gn;if((target_&3)||!IsExecutable(target_,16))throw std::runtime_error("ProcessEvent address is not aligned executable code");
        uint8_t bytes[16];if(!Read(target_,bytes,sizeof bytes)||BytesHex(bytes,16)!=Lower(p.at("process_event_prologue").get<std::string>()))throw std::runtime_error("ProcessEvent first 16 bytes mismatch");
        const auto& l=p.at("layout");layout_.kind=l.at("name_kind").get<std::string>();
        layout_.indirect=l.at("names_indirect");layout_.chunkSize=l.value("chunk_size",16384u);layout_.entryString=l.value("name_entry_string",16u);
        layout_.entryHeader=l.value("name_entry_header",8u);layout_.legacyHeaderCheck=l.value("legacy_header_check",true);
        layout_.objectName=l.at("object_name");layout_.objectClass=l.at("object_class");layout_.objectOuter=l.at("object_outer");layout_.functionFlags=l.at("function_flags");
        layout_.poolBlocks=l.value("pool_blocks",16u);layout_.poolBlockBits=l.value("pool_block_bits",16u);layout_.poolLengthShift=l.value("pool_length_shift",6u);
        if((layout_.kind!="legacy"&&layout_.kind!="pool")||layout_.indirect>2||layout_.chunkSize<1024||layout_.chunkSize>65536||layout_.entryString>128||layout_.entryHeader>128||layout_.objectName>256||layout_.objectClass>256||layout_.objectOuter>256||layout_.functionFlags>1024||layout_.poolBlocks>1024||layout_.poolBlockBits<8||layout_.poolBlockBits>20||layout_.poolLengthShift>10)throw std::runtime_error("Implausible profile layout");
        nameCache_.clear();if(Name(0)!="None")throw std::runtime_error("GNames validation failed: name index 0 is not None");
        long pageSize=sysconf(_SC_PAGESIZE);
        if(pageSize<4096||(pageSize&(pageSize-1)))throw std::runtime_error("Unsupported page size");
        uintptr_t page=target_&~(uintptr_t(pageSize)-1);
        if(target_-page>uintptr_t(pageSize)-16)throw std::runtime_error("ProcessEvent patch crosses a page boundary; profile refused");
        int protection=PageProtection(page,size_t(pageSize));
        if(protection<0||!(protection&PROT_EXEC))throw std::runtime_error("Cannot determine original executable-page permissions");
        CodeWriteGuard permissions(reinterpret_cast<void*>(page),size_t(pageSize),protection);
        if(!permissions.Enable())throw std::runtime_error(std::string("Code-page write permission refused: ")+strerror(errno));
        profileIdentity_=p.dump();
        hookAttempted_=true;
        int rc=DobbyHook(reinterpret_cast<void*>(target_),reinterpret_cast<void*>(&Hook),reinterpret_cast<void**>(&original_));
        if(!permissions.Restore())throw std::runtime_error("Cannot restore original code-page permissions; restart the target");
        if(rc!=0||!original_){profileIdentity_.clear();throw std::runtime_error("DobbyHook failed: "+std::to_string(rc));}
        uint8_t patched[16];
        if(!Read(target_,patched,sizeof patched)||memcmp(bytes,patched,sizeof bytes)==0)throw std::runtime_error("Hook entry patch could not be verified; restart the target");
        installed_.store(true,std::memory_order_release);return true;
    }catch(const std::exception&e){error=e.what();return false;}
}
ProcessEventTracer::Json ProcessEventTracer::Status(const char* type)const{
    return {{"type",type},{"protocol",1},{"agent_version",UE4TRACE_AGENT_VERSION},{"agent_build",UE4TRACE_BUILD_SHA},{"pid",getpid()},{"base",Hex(base_)},{"process_event",Hex(target_)},{"build_id",buildId_},{"hook_installed",installed_.load()},{"recording",recording_.load()},{"seen",seen_.load()},{"emitted",emitted_.load()},{"dropped",dropped_.load()},{"filtered",filtered_.load()},{"queued",queued_.load()},{"queue_capacity",Capacity},{"max_rate",maxRate_.load()},{"name_resolution","asynchronous; expired objects may not resolve"}};
}
ProcessEventTracer::Json ProcessEventTracer::Handle(const Json& c){
    Json rid=nullptr;
    try{
        if(!c.is_object())throw std::runtime_error("Command must be a JSON object");
        rid=c.value("request_id",Json(nullptr));
        if(!rid.is_number_integer())throw std::runtime_error("request_id must be an integer");
        auto cmd=c.at("cmd").get<std::string>();
        if(cmd=="configure"){
            if(recording_.load())throw std::runtime_error("Pause recording before configure");
            std::string error;if(!Configure(c.at("profile"),error))throw std::runtime_error(error);
            auto r=Status("configured");r["request_id"]=rid;r["ok"]=true;return r;
        }
        if(cmd=="start"){
            if(!installed_.load())throw std::runtime_error("Configure and validate profile first");
            auto inc=c.value("include",std::string()),exc=c.value("exclude",std::string());int rate=c.value("max_rate",1000);
            if(inc.size()>256||exc.size()>256||rate<1||rate>10000)throw std::runtime_error("Filter <=256 bytes; max_rate must be 1..10000");
            recording_.store(false,std::memory_order_release);epoch_.fetch_add(1);ClearQueue();
            include_=inc;exclude_=exc;maxRate_.store(rate);nextAdmissionUs_.store(0);recording_.store(true,std::memory_order_release);
            auto r=Status("started");r["ok"]=true;r["request_id"]=rid;return r;
        }
        if(cmd=="pause"||cmd=="stop"){
            recording_.store(false,std::memory_order_release);epoch_.fetch_add(1);ClearQueue();auto r=Status(cmd=="pause"?"paused":"stopped");r["ok"]=true;r["request_id"]=rid;r["hook_state"]=installed_.load()?"pass-through":"not-installed";return r;
        }
        if(cmd=="status"){auto r=Status();r["request_id"]=rid;r["ok"]=true;return r;}
        throw std::runtime_error("Unknown command");
    }catch(const std::exception&e){return {{"type","error"},{"request_id",rid},{"ok",false},{"message",e.what()}};}
}
ProcessEventTracer::Json ProcessEventTracer::Serialize(const Record&r){
    uintptr_t clazz=Pointer((r.object&PointerMask)+layout_.objectClass);
    std::string function=ObjectName(r.function,true),object=ObjectName(r.object,true),objectClass=ObjectName(clazz,false);
    auto text=function+" "+object+" "+objectClass;
    if((!include_.empty()&&text.find(include_)==std::string::npos)||(!exclude_.empty()&&text.find(exclude_)!=std::string::npos)){filtered_.fetch_add(1);return {};}
    return {{"type","event"},{"seq",++seq_},{"call_id",r.id},{"parent_id",r.parent},{"tid",r.tid},{"depth",r.depth},{"ts_us",r.started},{"duration_us",r.duration},{"function",function},{"object",object},{"object_class",objectClass},{"function_addr",Hex(r.function)},{"object_addr",Hex(r.object)},{"caller_rva",r.caller>=base_&&r.caller<moduleEnd_?Hex(r.caller-base_):std::string()},{"caller_addr",Hex(r.caller)},{"name_resolution","async"}};
}
bool ProcessEventTracer::Send(int socket,const Json& message){
    std::string data=message.dump(-1,' ',false,Json::error_handler_t::replace)+"\n";size_t offset=0;auto deadline=NowUs()+1500000;
    while(offset<data.size()){
        ssize_t sent=send(socket,data.data()+offset,data.size()-offset,MSG_NOSIGNAL|MSG_DONTWAIT);
        if(sent>0){offset+=size_t(sent);continue;}
        if(sent<0&&errno==EINTR)continue;
        if(sent<0&&(errno==EAGAIN||errno==EWOULDBLOCK)&&NowUs()<deadline){pollfd p{socket,POLLOUT,0};if(poll(&p,1,25)>=0)continue;}
        return false;
    }return true;
}
void ProcessEventTracer::StartServer(){
    bool expected=false;if(!serverStarted_.compare_exchange_strong(expected,true))return;
    try { std::thread([this]{
        try { Server(); }
        catch(const std::exception& e){recording_.store(false);epoch_.fetch_add(1);__android_log_print(ANDROID_LOG_ERROR,"UE4Trace","service stopped: %s",e.what());}
        catch(...){recording_.store(false);epoch_.fetch_add(1);__android_log_print(ANDROID_LOG_ERROR,"UE4Trace","service stopped after unexpected exception");}
        serverStarted_.store(false);
    }).detach(); } catch(...) { serverStarted_.store(false);throw; }
}
void ProcessEventTracer::Server(){
    agentThread=true;pthread_setname_np(pthread_self(),"ue4trace-io");
    int listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(listener<0)return;
    OwnedSocket listenerOwner(listener);
    sockaddr_un address{};address.sun_family=AF_UNIX;std::string name="ue4trace_"+std::to_string(getpid());memcpy(address.sun_path+1,name.data(),name.size());
    socklen_t len=offsetof(sockaddr_un,sun_path)+1+name.size();
    if(bind(listener,reinterpret_cast<sockaddr*>(&address),len)!=0||listen(listener,1)!=0){__android_log_print(ANDROID_LOG_ERROR,"UE4Trace","listen failed: %s",strerror(errno));return;}
    for(;;){
        int client=accept4(listener,nullptr,nullptr,SOCK_CLOEXEC|SOCK_NONBLOCK);if(client<0){if(errno==EINTR)continue;usleep(50000);continue;}
        OwnedSocket clientOwner(client);
        ucred peer{};socklen_t peerSize=sizeof(peer);
        if(getsockopt(client,SOL_SOCKET,SO_PEERCRED,&peer,&peerSize)!=0||(peer.uid!=0&&peer.uid!=2000&&peer.uid!=getuid())){continue;}
        int buffer=256*1024;setsockopt(client,SOL_SOCKET,SO_SNDBUF,&buffer,sizeof buffer);
        bool connected=Send(client,Status("hello"));std::string input;uint64_t lastStats=NowUs();
        while(connected){
            pollfd p{client,POLLIN,0};int ready=poll(&p,1,queued_.load()?0:10);
            if(ready<0){if(errno==EINTR)continue;break;}
            if(p.revents&(POLLERR|POLLHUP|POLLNVAL))break;
            if(p.revents&POLLIN){char buf[8192];ssize_t n=recv(client,buf,sizeof buf,0);if(n==0)break;if(n<0){if(errno!=EAGAIN&&errno!=EINTR)break;}else input.append(buf,size_t(n));
                if(input.size()>65536){Send(client,{{"type","error"},{"ok",false},{"message","Command exceeds 64 KiB"}});break;}
                for(size_t at;(at=input.find('\n'))!=std::string::npos;){auto line=input.substr(0,at);input.erase(0,at+1);if(line.empty())continue;Json c=Json::parse(line,nullptr,false);if(c.is_discarded()){connected=Send(client,{{"type","error"},{"ok",false},{"message","Invalid JSON"}});}else connected=Send(client,Handle(c));if(!connected)break;}
            }
            for(int n=0;connected&&n<64;++n){Record r;if(!Pop(r))break;if(!recording_.load()||r.epoch!=epoch_.load())continue;auto e=Serialize(r);if(e.is_null())continue;connected=Send(client,e);if(connected)emitted_.fetch_add(1);}
            if(connected&&NowUs()-lastStats>=1000000){connected=Send(client,Status("stats"));lastStats=NowUs();}
        }
        recording_.store(false,std::memory_order_release);epoch_.fetch_add(1);ClearQueue();
    }
}
extern "C" __attribute__((visibility("default"))) int ue4trace_init(){try{ProcessEventTracer::Instance().StartServer();return 0;}catch(...){return -1;}}
__attribute__((constructor)) static void StartTraceService(){ue4trace_init();}
