#pragma once
#include <cstdint>

// com.tencent.tmgp.pubgmhd 1.39.13 (16220), ARM64.
// libUE4.so GNU Build ID: 2d0c2e25ea80456aa1417850f45432d3ed5344c4
// RVAs relative to ELF load bias, NOT file offsets or absolute pointers.
namespace pubgmhd_1_39_13 {
static constexpr uintptr_t ProcessEvent = 0x0E016EAC;
static constexpr uintptr_t GActivity    = 0x175F2B78; // android_app* global slot
static constexpr uintptr_t GNames       = 0x176E6650; // legacy chunk table pointer slot
static constexpr uintptr_t GEngine      = 0x181BC008; // UEngine* global slot
static constexpr uintptr_t GUObject     = 0x17E8B538; // custom dumper compatibility anchor
static constexpr unsigned ProcessEventVTableIndex = 94;
static constexpr uintptr_t ProcessEventVTableByteOffset = 0x2F0;
// GUObject is NOT a complete standard GUObjectArray layout.
static constexpr uintptr_t ObjectItemsPointerAtAnchor = 0x10;
static constexpr uintptr_t ObjectItemStride = 0x18;
}
