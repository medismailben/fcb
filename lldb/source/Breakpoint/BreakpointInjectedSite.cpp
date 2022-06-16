//===-- BreakpointInjectedSite.cpp ------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Breakpoint/BreakpointInjectedSite.h"

#include "Plugins/ExpressionParser/Clang/ClangExpressionVariable.h"
#include "Plugins/ExpressionParser/Clang/ClangUserExpression.h"
#include "lldb/Expression/ExpressionVariable.h"
#include "lldb/Target/Language.h"

#include "lldb/Target/ABI.h"

#include "llvm/Support/DataExtractor.h"

using namespace lldb;
using namespace lldb_private;

BreakpointInjectedSite::BreakpointInjectedSite(
    BreakpointSiteList *list, const BreakpointLocationSP &owner,
    lldb::addr_t addr)
    : BreakpointSite(list, owner, addr, false, eKindBreakpointInjectedSite),
      m_target_sp(owner->GetTarget().shared_from_this()),
      m_real_addr(owner->GetAddress()), m_trap_addr(LLDB_INVALID_ADDRESS) {}

BreakpointInjectedSite::~BreakpointInjectedSite() {}

bool BreakpointInjectedSite::BuildConditionExpression(void) {
  Log *log = GetLog(LLDBLog::JITLoader);

  Status error;

  std::string trap;
  std::string condition_text;
  bool single_condition = true;

  LanguageType language = eLanguageTypeUnknown;

  for (BreakpointLocationSP loc_sp : m_owners.BreakpointLocations()) {

    // Stop building the expression if a location condition is not JIT-ed
    if (!loc_sp->GetInjectCondition()) {
      LLDB_LOG(log, "FCB: BreakpointLocation ({}) condition is not JIT-ed",
               loc_sp->GetConditionText());
      return false;
    }

    std::string condition = loc_sp->GetConditionText();
    // See if we can figure out the language from the frame, otherwise use the
    // default language:
    CompileUnit *comp_unit =
        loc_sp->GetAddress().CalculateSymbolContextCompileUnit();
    if (comp_unit)
      language = comp_unit->GetLanguage();

    if (language == eLanguageTypeSwift) {
      trap += "Builtin.int_trap()";
    } else if (Language::LanguageIsCFamily(language)) {
      trap = "__builtin_debugtrap()";
    } else {
      LLDB_LOG(log, "FCB: Language {} not supported",
               Language::GetNameForLanguageType(language));
      m_condition_expression_sp.reset();
      return false;
    }

    condition_text += (single_condition) ? "if (" : " || ";
    condition_text += condition;

    single_condition = false;
  }

  condition_text += ") {\n\t";

  condition_text += trap + ";\n    }";

  LLDB_LOGV(log, "Injected Condition:\n{}\n", condition_text.c_str());

  DiagnosticManager diagnostics;

  EvaluateExpressionOptions options;
  options.SetInjectCondition(true);
  options.SetKeepInMemory(true);
  options.SetGenerateDebugInfo(true);

  m_condition_expression_sp.reset(m_target_sp->GetUserExpressionForLanguage(
      condition_text, llvm::StringRef(), language, Expression::eResultTypeAny,
      EvaluateExpressionOptions(options), nullptr, error));

  if (error.Fail()) {
    if (log)
      log->Printf("Error getting condition expression: %s.", error.AsCString());
    m_condition_expression_sp.reset();
    return false;
  }

  diagnostics.Clear();

  ThreadSP thread_sp = m_target_sp->GetProcessSP()
                           ->GetThreadList()
                           .GetExpressionExecutionThread();

  user_id_t frame_idx = -1;
  user_id_t concrete_frame_idx = -1;
  addr_t cfa = LLDB_INVALID_ADDRESS;
  bool cfa_is_valid = false;
  addr_t pc = LLDB_INVALID_ADDRESS;
  StackFrame::Kind frame_kind = StackFrame::Kind::Regular;
  bool zeroth_frame = false;
  SymbolContext sc;
  m_real_addr.CalculateSymbolContext(&sc);

  StackFrameSP frame_sp = std::make_shared<StackFrame>(
      thread_sp, frame_idx, concrete_frame_idx, cfa, cfa_is_valid, pc,
      frame_kind, zeroth_frame, &sc);

  m_owner_exe_ctx = ExecutionContext(frame_sp);
  ExecutionPolicy execution_policy = eExecutionPolicyAlways;
  bool keep_result_in_memory = true;
  bool generate_debug_info = true;

  if (!m_condition_expression_sp->Parse(diagnostics, m_owner_exe_ctx,
                                        execution_policy, keep_result_in_memory,
                                        generate_debug_info)) {
    LLDB_LOG(log, "Couldn't parse conditional expression:\n{}",
             diagnostics.GetString().c_str());
    m_condition_expression_sp.reset();
    return false;
  }

  const AddressRange &jit_addr_range =
      m_condition_expression_sp->GetJITAddressRange();

  error.Clear();

  void *buffer = std::calloc(jit_addr_range.GetByteSize(), sizeof(uint8_t));

  lldb::addr_t jit_addr =
      jit_addr_range.GetBaseAddress().GetCallableLoadAddress(m_target_sp.get());

  size_t memory_read = m_target_sp->GetProcessSP()->ReadMemory(
      jit_addr, buffer, jit_addr_range.GetByteSize(), error);

  if (memory_read != jit_addr_range.GetByteSize() || error.Fail()) {
    m_condition_expression_sp.reset();
    error.SetErrorString("Couldn't read jit memory");
    return false;
  }

  PlatformSP platform_sp = m_target_sp->GetPlatform();

  if (!platform_sp) {
    error.SetErrorString("Couldn't get running platform");
    return false;
  }

  if (!platform_sp->GetSoftwareBreakpointTrapOpcode(*m_target_sp.get(), this)) {
    error.SetErrorString("Couldn't get current architecture trap opcode");
    return false;
  }

  if (!ResolveTrapAddress(buffer, memory_read)) {
    error.SetErrorString("Couldn't find trap in jitter expression");
    return false;
  }

  if (!GatherArgumentsMetadata()) {
    LLDB_LOG(log, "FCB: Couldn't gather argument metadata");
    return false;
  }

  if (!CreateArgumentsStructure()) {
    LLDB_LOG(log, "FCB: Couldn't create argument structure");
    return false;
  }

  return true;
}

bool BreakpointInjectedSite::ResolveTrapAddress(void *jit, size_t size) {
  Log *log = GetLog(LLDBLog::JITLoader);

  const ABISP abi_sp = m_target_sp->GetProcessSP()->GetABI();
  const ArchSpec &arch = m_target_sp->GetArchitecture();
  const char *plugin_name = nullptr;
  const char *flavor = nullptr;
  const bool prefer_file_cache = true;

  m_disassembler_sp = Disassembler::DisassembleRange(
      arch, plugin_name, flavor, *m_target_sp.get(),
      m_condition_expression_sp->GetJITAddressRange(), prefer_file_cache);

  if (!m_disassembler_sp) {
    LLDB_LOG(log, "FCB: Couldn't disassemble JIT-ed expression");
    return false;
  }

  InstructionList &instructions = m_disassembler_sp->GetInstructionList();

  if (!instructions.GetSize()) {
    LLDB_LOG(log, "FCB: No instructions found for JIT-ed expression");
    return false;
  }

  auto abi_debug_trap_opcode = abi_sp->GetDebugTrapOpcode();

  for (size_t i = 0; i < instructions.GetSize(); i++) {
    InstructionSP instr = instructions.GetInstructionAtIndex(i);

    DataExtractor data;
    instr->GetData(data);

    const size_t trap_size = instr->Decode(*m_disassembler_sp.get(), data, 0);

    const void *instr_opcode = instr->GetOpcode().GetOpcodeDataBytes();

    if (!instr_opcode) {
      return false;
    }

    if (!abi_debug_trap_opcode) {
      LLDB_LOG(log, "FCB: No ABI debug_trap opcode found.");
      return false;
    }

    // Within a same platform, the compiler can generate different opcodes for
    // the same debug trap builtin. https://reviews.llvm.org/D84014
    for (auto &abi_trap_code : *abi_debug_trap_opcode) {
      if (!memcmp(instr_opcode, abi_trap_code.data(), trap_size)) {
        addr_t addr =
            instr->GetAddress().GetOpcodeLoadAddress(m_target_sp.get());
        m_trap_addr = addr;
        LLDB_LOGV(log, "Injected trap address: {0:X+}", addr);
        return true;
      }
    }
  }
  return false;
}

bool BreakpointInjectedSite::GatherArgumentsMetadata() {
  Log *log = GetLog(LLDBLog::JITLoader);

  LanguageType native_language = m_condition_expression_sp->Language();

  if (!Language::LanguageIsCFamily(native_language)) {
    LLDB_LOG(log, "FCB: {} language does not support Injected Conditional \
             Breapoint",
             Language::GetNameForLanguageType(native_language));
    return false;
  }

  ClangUserExpression *clang_expr =
      llvm::dyn_cast<ClangUserExpression>(m_condition_expression_sp.get());

  ClangExpressionDeclMap *decl_map = clang_expr->DeclMap();
  if (!decl_map) {
    LLDB_LOG(log, "FCB: Couldn't find DeclMap for JIT-ed expression");
    return false;
  }

  if (!decl_map->DoStructLayout()) {
    LLDB_LOG(log, "FCB: Couldn't finalize DeclMap Struct Layout");
    return false;
  }

  uint32_t num_elements;
  size_t size;
  offset_t alignment;

  if (!decl_map->GetStructInfo(num_elements, size, alignment)) {
    LLDB_LOG(log, "FCB: Couldn't fetch arguments info from DeclMap");
    return false;
  }

  ExpressionVariableList &members = decl_map->GetStructMembers();

  for (uint32_t i = 0; i < num_elements; ++i) {
    const clang::NamedDecl *decl = nullptr;
    llvm::Value *value = nullptr;
    lldb::offset_t offset;
    lldb_private::ConstString name;

    if (!decl_map->GetStructElement(decl, value, offset, name, i)) {
      LLDB_LOG(log, "FCB: Couldn't fetch element from DeclMap");
      return false;
    }
    if (!value) {
      LLDB_LOG(log, "FCB: Couldn't find value for element {}/{}", i,
               num_elements);
      return false;
    }

    ExpressionVariableSP expr_var = members.GetVariableAtIndex(i);

    if (!expr_var) {
      LLDB_LOG(
          log,
          "FCB: Couldn't find expression variable for element '{}' ({}/{})",
          name, i, num_elements);
      return false;
    }

    ValueObjectSP val_obj_sp = expr_var->GetValueObject();

    if (!val_obj_sp->GetVariable()) {
      // if Expression Variable does not have ValueObject, skip it
      continue;
    }

    VariableSP var_sp = val_obj_sp->GetVariable();

    DWARFExpression lldb_dwarf_expr = var_sp->LocationExpression();
    DataExtractor lldb_data;
    if (!lldb_dwarf_expr.GetExpressionData(lldb_data)) {
      return false;
    }

    llvm::StringRef data(lldb_data.PeekCStr(0));
    bool is_le = (lldb_data.GetByteOrder() == lldb::eByteOrderLittle);
    uint32_t data_addr_size = lldb_data.GetAddressByteSize();
    llvm::DataExtractor llvm_data =
        llvm::DataExtractor(data, is_le, data_addr_size);

    uint8_t addr_size = m_target_sp->GetArchitecture().GetAddressByteSize();

    auto size = var_sp->GetType()->GetByteSize(m_target_sp.get());
    if (!size) {
      LLDB_LOG(log, "FCB: Variable {} has invalid size",
               var_sp->GetName().GetCString());
      return false;
    }

    VariableMetadata metadata(expr_var->GetName().GetCString(), size.getValue(),
                              llvm_data, addr_size);

    m_metadatas.push_back(metadata);
  }

  clang_expr->ResetDeclMap();

  return true;
}

bool BreakpointInjectedSite::CreateArgumentsStructure() {
  Log *log = GetLog(LLDBLog::JITLoader);

  Status error;
  std::string expr;
  expr.reserve(2048);
  std::string name = "$__lldb_create_args_struct";

  ABISP abi_sp = m_owner_exe_ctx.GetProcessSP()->GetABI();

  expr += "extern \"C\"\n"
          "{\n"
          "   /*\n"
          "   * defines\n"
          "   */\n"
          "\n"
          "   void* memcpy (void *dest, const void *src, size_t count);\n"
          "}\n\n";

  expr += abi_sp->GetRegisterContextAsString();

  expr += "\n\n"
          "intptr_t $__lldb_create_args_struct(register_context* regs, "
          "intptr_t arg_struct) {\n"
          "   void *src_addr = NULL;\n"
          "   void *dst_addr = NULL;\n"
          "   size_t count = sizeof(void*);\n"
          "\n";

  for (size_t index = 0; index < m_metadatas.size(); index++) {
    expr += ParseDWARFExpression(index, error);
    if (error.Fail()) {
      LLDB_LOG(log, "FCB: Couldn't parse DWARFExpression ({0}/{1})", index,
               m_metadatas.size());
      return false;
    }
  }

  expr += "\n";

  expr += "   return arg_struct;\n"
          "}\n";

  auto utility_fn_or_error = m_target_sp->CreateUtilityFunction(
      expr, name, eLanguageTypeC, m_owner_exe_ctx);

  if (!utility_fn_or_error) {
    std::string error_str = llvm::toString(utility_fn_or_error.takeError());
    LLDB_LOG(log, "Error getting utility function: {1}.", error_str);
    m_create_args_struct_function_sp.reset();
    return false;
  }

  m_create_args_struct_function_sp = std::move(*utility_fn_or_error);

  return true;
}

std::string BreakpointInjectedSite::ParseDWARFExpression(size_t index,
                                                         Status &error) {
  std::string expr;
  ABISP abi_sp = m_owner_exe_ctx.GetProcessSP()->GetABI();

  for (auto op : m_metadatas[index].dwarf) {
    switch (op.getCode()) {
    case llvm::dwarf::DW_OP_addr: {
      int64_t operand = op.getRawOperand(0);
      expr += "   src_addr = " + std::to_string(operand) +
              ";\n"
              "   dst_addr = (void*) (arg_struct + " +
              std::to_string(index * 8) +
              ");\n"
              "   memcpy(dst_addr, &src_addr, count);\n";
      break;
    }
    case llvm::dwarf::DW_OP_fbreg: {
      int64_t operand = op.getRawOperand(0);
      const char *frame_ptr;
      abi_sp->GetFramePointerRegister(frame_ptr);
      expr += "   src_addr = (void*) (regs->" + std::string(frame_ptr) + " + " +
              std::to_string(operand) +
              ");\n"
              "   dst_addr = (void*) (arg_struct + " +
              std::to_string(index * 8) +
              ");\n"
              "   memcpy(dst_addr, &src_addr, count);\n";
      break;
    }
    default: {
      error.Clear();
      //      error.SetErrorToErrno();
      break;
    }
    }
  }

  return expr;
}
