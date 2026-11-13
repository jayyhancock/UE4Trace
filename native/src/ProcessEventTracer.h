#pragma once
#include <atomic>
#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <nlohmann/json.hpp>

// Observation only. The trampoline is retained for the lifetime of the process.
class ProcessEventTracer final {
public:
    using Json = nlohmann::json;
    using ProcessEvent = void (*)(void*, void*, void*);
    static ProcessEventTracer& Instance();
    void StartServer();
    static void Hook(void* object, void* function, void* parameters);
private:
    struct Record {
        uint64_t id, parent, started, duration, epoch;
        uintptr_t object, function, caller;
        uint32_t tid, depth;
    };
    struct Layout {
        std::string kind;
        uint32_t indirect=1, chunkSize=16384, entryString=16;
        uint32_t entryHeader=8;
        bool legacyHeaderCheck=true;
        uint32_t objectName=24, objectClass=16, objectOuter=32, functionFlags=176;
        uint32_t poolBlocks=16, poolBlockBits=16, poolLengthShift=6;
    } layout_;
    ProcessEventTracer();
    bool Read(uintptr_t address, void* destination, size_t length) const;
    uintptr_t Pointer(uintptr_t address) const;
    std::string CString(uintptr_t address, size_t cap=256) const;
    std::string Name(uint32_t id);
    std::string ObjectName(uintptr_t object, bool path);
    bool Push(const Record& record);
    bool Pop(Record& record);
    void ClearQueue();
    void Server();
    bool Configure(const Json& profile, std::string& error);
    Json Status(const char* type="status") const;
    Json Handle(const Json& command);
    Json Serialize(const Record& record);
    bool Send(int socket, const Json& message);
    bool IsExecutable(uintptr_t address, size_t length) const;
    static constexpr size_t Capacity=8192;
    std::array<Record, Capacity> queue_{};
    std::atomic_flag queueLock_=ATOMIC_FLAG_INIT;
    size_t readIndex_=0, writeIndex_=0;
    std::atomic<size_t> queued_{0};
    std::atomic<bool> recording_{false}, installed_{false}, serverStarted_{false};
    std::atomic<uint64_t> epoch_{0}, calls_{0}, seen_{0}, emitted_{0}, dropped_{0}, filtered_{0};
    std::atomic<uint64_t> nextAdmissionUs_{0};
    std::atomic<uint32_t> maxRate_{1000};
    alignas(8) ProcessEvent original_=nullptr;
    bool hookAttempted_=false;
    uintptr_t base_=0, moduleEnd_=0, target_=0, names_=0;
    std::vector<std::pair<uintptr_t,uintptr_t>> executableRanges_;
    std::string buildId_, profileIdentity_, include_, exclude_, package_, module_;
    uint64_t seq_=0;
    int memoryFd_=-1;
    std::unordered_map<uint32_t,std::string> nameCache_;
};
