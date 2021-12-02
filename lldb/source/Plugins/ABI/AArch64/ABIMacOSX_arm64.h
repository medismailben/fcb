//===-- ABIMacOSX_arm64.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_ABI_AARCH64_ABIMACOSX_ARM64_H
#define LLDB_SOURCE_PLUGINS_ABI_AARCH64_ABIMACOSX_ARM64_H

#include "Plugins/ABI/AArch64/ABIAArch64.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/lldb-private.h"

class ABIMacOSX_arm64 : public ABIAArch64 {
public:
  static constexpr const uint8_t aarch64_jmp_opcode = 0xE9;
  static constexpr const uint8_t aarch64_call_opcode = 0xE8;
  static constexpr const uint8_t aarch64_mov_opcode = 0x89;
  static constexpr const uint8_t aarch64_sub_opcode = 0x83;
  static constexpr const uint8_t aarch64_add_opcode = 0x83;

  static constexpr const uint8_t aarch64_push_opcode = 0x50;
  static constexpr const uint8_t aarch64_pop_opcode = 0x58;

  static constexpr const std::size_t aarch64_instr_size = 4;
  static constexpr const std::size_t aarch64_saved_register_size = 24;
  static constexpr const std::size_t aarch64_volatile_register_size = 8;
  
  
  // https://github.com/apple/darwin-xnu/blob/main/osfmk/arm64/cswitch.s
  // https://github.com/RTEMS/rtems/blob/master/cpukit/score/cpu/aarch64/cpu_asm.S
  /// STP X0, X1, [SP, #-16]! ; Push X0 and X1 onto the stack
  /// LDP X0, X1, [SP], #16 ; Pop X0 and X1 from the stack
  static constexpr const char* cs_save_registers = R"(
                                                      str x0,  [x0]
                                                      stp x1, x2, [x0, #0x10]
                                                      stp x3, x4, [x0, #0x20]
                                                      stp x5, x6, [x0, #0x30]
                                                      stp x7, x8, [x0, #0x40]
                                                      stp x9, x10, [x0, #0x50]
                                                      stp x11, x12, [x0, #0x60]
                                                      stp x13, x14, [x0, #0x70]
                                                      stp x15, x16, [x0, #0x80]
                                                      stp x17, x18, [x0, #0x90]
                                                      stp x19, x20, [x0, #0x100]
                                                      stp x21, x22, [x0, #0x110]
                                                      stp x23, x24, [x0, #0x120]
                                                      stp x25, x26, [x0, #0x130]
                                                      stp x27, x28, [x0, #0x140]
                                                      stp fp,  lr,  [x0, #0x150]
                                                      mov x4,  sp
                                                      str x4,  [x0, #0x160])";
  
  static constexpr const char* cs_load_registers = R"(
                                                      ldr x0,  [x1]
                                                      ldp x1, x2, [x1, #0x10]
                                                      ldp x3, x4, [x1, #0x20]
                                                      ldp x5, x6, [x1, #0x30]
                                                      ldp x7, x8, [x1, #0x40]
                                                      ldp x9, x10, [x1, #0x50]
                                                      ldp x11, x12, [x1, #0x60]
                                                      ldp x13, x14, [x1, #0x70]
                                                      ldp x15, x16, [x1, #0x80]
                                                      ldp x17, x18, [x1, #0x90]
                                                      ldp x19, x20, [x1, #0x100]
                                                      ldp x21, x22, [x1, #0x110]
                                                      ldp x23, x24, [x1, #0x120]
                                                      ldp x25, x26, [x1, #0x130]
                                                      ldp x27, x28, [x1, #0x140]
                                                      ldp fp,  lr,  [x1, #0x150]
                                                      ldr x4,  [x1, #0x160]
                                                      mov sp,  x4)";
  
  llvm::StringRef GetCSSaveRegistersAssembly() override { return cs_save_registers; }
  
  llvm::StringRef GetCSLoadRegistersAssembly() override { return cs_load_registers; }

  static constexpr const char *register_context = R"(typedef struct {
                                                      intptr_t sp;
                                                      intptr_t lr;
                                                      intptr_t fp;
                                                      intptr_t x28;
                                                      intptr_t x27;
                                                      intptr_t x26;
                                                      intptr_t x25;
                                                      intptr_t x24;
                                                      intptr_t x23;
                                                      intptr_t x22;
                                                      intptr_t x21;
                                                      intptr_t x20;
                                                      intptr_t x19;
                                                      intptr_t x18;
                                                      intptr_t x17;
                                                      intptr_t x16;
                                                      intptr_t x15;
                                                      intptr_t x14;
                                                      intptr_t x13;
                                                      intptr_t x12;
                                                      intptr_t x11;
                                                      intptr_t x10;
                                                      intptr_t x9;
                                                      intptr_t x8;
                                                      intptr_t x7;
                                                      intptr_t x6;
                                                      intptr_t x5;
                                                      intptr_t x4;
                                                      intptr_t x3;
                                                      intptr_t x2;
                                                      intptr_t x1;
                                                      intptr_t x0;
                                                      } register_context;)";

  ~ABIMacOSX_arm64() override = default;

  size_t GetRedZoneSize() const override;

  bool PrepareTrivialCall(lldb_private::Thread &thread, lldb::addr_t sp,
                          lldb::addr_t functionAddress,
                          lldb::addr_t returnAddress,
                          llvm::ArrayRef<lldb::addr_t> args) const override;

  bool GetArgumentValues(lldb_private::Thread &thread,
                         lldb_private::ValueList &values) const override;

  bool
  CreateFunctionEntryUnwindPlan(lldb_private::UnwindPlan &unwind_plan) override;

  bool CreateDefaultUnwindPlan(lldb_private::UnwindPlan &unwind_plan) override;

  bool RegisterIsVolatile(const lldb_private::RegisterInfo *reg_info) override;

  // The arm64 ABI requires that stack frames be 16 byte aligned.
  // When there is a trap handler on the stack, e.g. _sigtramp in userland
  // code, we've seen that the stack pointer is often not aligned properly
  // before the handler is invoked.  This means that lldb will stop the unwind
  // early -- before the function which caused the trap.
  //
  // To work around this, we relax that alignment to be just word-size
  // (8-bytes).
  // Allowing the trap handlers for user space would be easy (_sigtramp) but
  // in other environments there can be a large number of different functions
  // involved in async traps.
  bool CallFrameAddressIsValid(lldb::addr_t cfa) override {
    // Make sure the stack call frame addresses are are 8 byte aligned
    if (cfa & (8ull - 1ull))
      return false; // Not 8 byte aligned
    if (cfa == 0)
      return false; // Zero is not a valid stack address
    return true;
  }

  bool CodeAddressIsValid(lldb::addr_t pc) override {
    if (pc & (4ull - 1ull))
      return false; // Not 4 byte aligned

    // Anything else if fair game..
    return true;
  }

  bool GetFramePointerRegister(const char *&name) override;

  lldb::addr_t FixAddress(lldb::addr_t pc, lldb::addr_t mask) override;

  /// Allocate a memory stub for the fast condition breakpoint trampoline, and
  /// build it by saving the register context, calling the argument structure
  /// builder, passing the resulting structure to the condition checker,
  /// restoring the register context, running the copied instructions and]
  /// jumping back to the user source code.
  ///
  /// \param[in] instrs_size
  ///    The size in bytes of the copied instructions.
  ///
  /// \param[in] data
  ///    The copied instructions buffer.
  ///
  /// \param[in] jmp_addr
  ///    The address of the source .
  ///
  /// \param[in] util_func_addr
  ///    The address of the JIT-ed argument structure builder.
  ///
  /// \param[in] cond_expr_addr
  ///    The address of the JIT-ed condition checker.
  ///
  /// \return
  ///    \b true If building the Trampoline succeeded, \b false otherwise.
  ///
  bool SetupFastConditionalBreakpointTrampoline(
      size_t instrs_size, uint8_t *instrs_data,
      lldb_private::BreakpointInjectedSite *bp_inject_site) override;
  

  size_t GetJumpSize() override { return aarch64_instr_size; }

  llvm::StringRef GetRegisterContextAsString() override {
    return register_context;
  }

  bool SupportsFCB() override { return true; }

  // Static Functions

  static void Initialize();

  static void Terminate();

  static lldb::ABISP CreateInstance(lldb::ProcessSP process_sp, const lldb_private::ArchSpec &arch);

  // PluginInterface protocol

  static llvm::StringRef GetPluginNameStatic() { return "ABIMacOSX_arm64"; }

  llvm::StringRef GetPluginName() override { return GetPluginNameStatic(); }

  lldb_private::Status
  SetReturnValueObject(lldb::StackFrameSP &frame_sp,
                       lldb::ValueObjectSP &new_value) override;

protected:
  lldb::ValueObjectSP
  GetReturnValueObjectImpl(lldb_private::Thread &thread,
                           lldb_private::CompilerType &ast_type) const override;

private:
  using ABIAArch64::ABIAArch64; // Call CreateInstance instead.
};

#endif // LLDB_SOURCE_PLUGINS_ABI_AARCH64_ABIMACOSX_ARM64_H
