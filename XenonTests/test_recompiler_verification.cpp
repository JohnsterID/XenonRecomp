#include <gtest/gtest.h>
#include <XenonUtils/xex.h>
#include <XenonRecomp/recompiler.h>
#include <disasm.h>  // PPC disassembly header
using namespace XenonUtils;

class BasicSanityTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // Initialize shared resources
        ppc_disasm_init();
    }
};

TEST_F(BasicSanityTest, XEXHeaderValidation) {
    XEXHeader header{};
    header.magic = XEX_HEADER_MAGIC;
    header.module_flags = 0x100;
    header.entry_point = 0x82000000;
    EXPECT_TRUE(ValidateXEXHeader(header));
}

TEST_F(BasicSanityTest, DisasmInitialization) {
    ppc_instruction_t instr = ppc_disasm(0x48000000);
    EXPECT_EQ(instr.opcode, PPC_OPCODE_BRANCH) 
        << "Received opcode: " << instr.opcode 
        << ", Expected: " << PPC_OPCODE_BRANCH;
}