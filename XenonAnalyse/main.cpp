#include "fmt/xchar.h"
#include "function.h"
#include <algorithm>
#include <cassert>
#include <disasm.h>
#include <file.h>
#include <image.h>
#include <xbox.h>
#include <symbol_resolver.h>
#include <map>
#include <filesystem>

#define SWITCH_ABSOLUTE 0
#define SWITCH_COMPUTED 1
#define SWITCH_BYTEOFFSET 2
#define SWITCH_SHORTOFFSET 3

struct SwitchTable
{
    std::vector<size_t> labels{};
    size_t base{};
    size_t defaultLabel{};
    uint32_t r{};
    uint32_t type{};
};

static const uint8_t RESTGPRLR_14[] = { 0xe9, 0xc1, 0xff, 0x68 };
static const uint8_t SAVEGPRLR_14[] = { 0xf9, 0xc1, 0xff, 0x68 };
static const uint8_t RESTFPR_14[] = { 0xc9, 0xcc, 0xff, 0x70 };
static const uint8_t SAVEFPR_14[] = { 0xd9, 0xcc, 0xff, 0x70 };
static const uint8_t RESTVMX_14[] = { 0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x60, 0xce };
static const uint8_t SAVEVMX_14[] = { 0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x61, 0xce };
static const uint8_t RESTVMX_64[] = { 0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x60, 0xcb };
static const uint8_t SAVEVMX_64[] = { 0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x61, 0xcb };

uint32_t BytePatternSearch(uint8_t* data, const uint32_t dataSize, const uint32_t baseAddress, const uint8_t pattern[], const size_t patternSize)
{
    auto result = std::search(data, data + dataSize, pattern, pattern + patternSize);
    if (result != data + dataSize) {
        return baseAddress + std::distance(data, result);
    }

    return UINT32_MAX;
}

void RegisterFunctionsSearch(Image& image)
{
    uint32_t baseAddress = UINT32_MAX;

    // fmt::println("DEBUG: Available sections in RegisterFunctionsSearch:");
    // for (const auto& section : image.sections) {
    //     fmt::println("  - Section: '{}', base: 0x{:X}, size: {}", section.name, section.base, section.size);
    // }

    for (const auto& section : image.sections) {
        if (section.name == ".text") {
            baseAddress = section.base;

            if (baseAddress == UINT32_MAX) {
                fmt::println("Could not find \".text\" section.");
                return;
            }

            uint32_t restgprlr_14 = BytePatternSearch(section.data, section.size, baseAddress, RESTGPRLR_14, sizeof(RESTGPRLR_14));
            uint32_t savegprlr_14 = BytePatternSearch(section.data, section.size, baseAddress, SAVEGPRLR_14, sizeof(SAVEGPRLR_14));
            uint32_t restfpr_14 = BytePatternSearch(section.data, section.size, baseAddress, RESTFPR_14, sizeof(RESTFPR_14));
            uint32_t savefpr_14 = BytePatternSearch(section.data, section.size, baseAddress, SAVEFPR_14, sizeof(SAVEFPR_14));
            uint32_t restvmx_14 = BytePatternSearch(section.data, section.size, baseAddress, RESTVMX_14, sizeof(RESTVMX_14));
            uint32_t savevmx_14 = BytePatternSearch(section.data, section.size, baseAddress, SAVEVMX_14, sizeof(SAVEVMX_14));
            uint32_t restvmx_64 = BytePatternSearch(section.data, section.size, baseAddress, RESTVMX_64, sizeof(RESTVMX_64));
            uint32_t savevmx_64 = BytePatternSearch(section.data, section.size, baseAddress, SAVEVMX_64, sizeof(SAVEVMX_64));

            fmt::println("restgprlr_14_address = 0x{:X}", restgprlr_14);
            fmt::println("savegprlr_14_address = 0x{:X}", savegprlr_14);
            fmt::println("restfpr_14_address = 0x{:X}", restfpr_14);
            fmt::println("savefpr_14_address = 0x{:X}", savefpr_14);
            fmt::println("restvmx_14_address = 0x{:X}", restvmx_14);
            fmt::println("savevmx_14_address = 0x{:X}", savevmx_14);
            fmt::println("restvmx_64_address = 0x{:X}", restvmx_64);
            fmt::println("savevmx_64_address = 0x{:X}", savevmx_64);
        }
    }
}

void LongJmpSetJmpSearch(Image& image)
{
    uint32_t baseAddress = UINT32_MAX;
    const uint8_t* data = nullptr;
    uint32_t dataSize = 0;

    for (const auto& section : image.sections) {
        // fmt::println("DEBUG: Found section: {}", section.name);
        if (section.name == ".text") {
            baseAddress = section.base;
            data = section.data;
            dataSize = section.size;
            break;
        }
    }

    if (baseAddress == UINT32_MAX || data == nullptr) {
        fmt::println("ERROR: .text section not found for longjmp/setjmp search");
        fmt::println("Available sections:");
        for (const auto& section : image.sections) {
            fmt::println("  - {}", section.name);
        }
        return;
    }

    fmt::println("# ---- LONGJMP/SETJMP FUNCTIONS ----");

    // Pattern 1: setjmp - look for mflr r0 followed by floating-point register saves
    // This pattern: mflr r0; mfcr r0; stfd f14, 0(r3); stfd f15, 8(r3); ...
    static const uint8_t SETJMP_PATTERN[] = { 0x7c, 0x08, 0x02, 0xa6, 0x7c, 0x80, 0x00, 0x26, 0xd9, 0xc3, 0x00, 0x00 };
    
    // Pattern 2: longjmp - look for floating-point register loads followed by mtlr r0; blr
    // This pattern: lfd f14, 0(r3); lfd f15, 8(r3); ... mtlr r0; blr
    static const uint8_t LONGJMP_PATTERN1[] = { 0xc9, 0xc3, 0x00, 0x00, 0xc9, 0xe3, 0x00, 0x08 }; // lfd f14,0(r3); lfd f15,8(r3)
    static const uint8_t LONGJMP_PATTERN2[] = { 0x7c, 0x08, 0x03, 0xa6, 0x4e, 0x80, 0x00, 0x20 }; // mtlr r0; blr
    
    // Pattern 3: Alternative setjmp - simple li r3, 0; blr in C runtime area
    static const uint8_t SETJMP_SIMPLE[] = { 0x38, 0x60, 0x00, 0x00, 0x4e, 0x80, 0x00, 0x20 }; // li r3, 0; blr

    uint32_t setjmpAddress = UINT32_MAX;
    uint32_t longjmpAddress = UINT32_MAX;

    // Search for setjmp pattern (mflr r0; mfcr r0; stfd f14, 0(r3))
    uint32_t setjmpOffset = BytePatternSearch(const_cast<uint8_t*>(data), dataSize, baseAddress, SETJMP_PATTERN, sizeof(SETJMP_PATTERN));
    if (setjmpOffset != UINT32_MAX) {
        setjmpAddress = setjmpOffset;
        fmt::println("setjmp_address = 0x{:X}", setjmpAddress);
    }

    // Search for longjmp pattern - look for functions with FPR loads
    for (uint32_t i = 0; i < dataSize - sizeof(LONGJMP_PATTERN1) - 64; i += 4) {
        // Look for the FPR load pattern
        if (std::equal(LONGJMP_PATTERN1, LONGJMP_PATTERN1 + sizeof(LONGJMP_PATTERN1), data + i)) {
            // Look ahead for mtlr r0; blr within reasonable distance
            for (uint32_t j = i + sizeof(LONGJMP_PATTERN1); j < i + 256 && j < dataSize - sizeof(LONGJMP_PATTERN2); j += 4) {
                if (std::equal(LONGJMP_PATTERN2, LONGJMP_PATTERN2 + sizeof(LONGJMP_PATTERN2), data + j)) {
                    // Found a potential longjmp function
                    // Look backwards for function start
                    uint32_t funcStart = i;
                    for (int k = 1; k <= 16 && funcStart >= 4; k++) {
                        funcStart -= 4;
                        uint32_t word = (data[funcStart] << 24) | (data[funcStart + 1] << 16) | 
                                       (data[funcStart + 2] << 8) | data[funcStart + 3];
                        if ((word & 0xFFFF0000) == 0x94210000) { // stwu r1, -offset(r1)
                            longjmpAddress = baseAddress + funcStart;
                            fmt::println("longjmp_address = 0x{:X}", longjmpAddress);
                            goto longjmp_found;
                        }
                    }
                }
            }
        }
    }
    longjmp_found:

    // If we didn't find the complex patterns, look for simpler ones
    if (setjmpAddress == UINT32_MAX) {
        // Look for simple setjmp pattern in C runtime area (around 0x82497A54 based on analysis)
        // Search for clusters of li r3, 0; blr patterns
        std::vector<uint32_t> simpleCandidates;
        for (uint32_t i = 0; i < dataSize - sizeof(SETJMP_SIMPLE); i += 4) {
            if (std::equal(SETJMP_SIMPLE, SETJMP_SIMPLE + sizeof(SETJMP_SIMPLE), data + i)) {
                simpleCandidates.push_back(i);
            }
        }
        
        // Look for the area with the highest density of these patterns (C runtime area)
        if (!simpleCandidates.empty()) {
            // Find the area with most consecutive patterns
            uint32_t bestStart = 0;
            uint32_t bestCount = 0;
            
            for (size_t i = 0; i < simpleCandidates.size(); i++) {
                uint32_t count = 1;
                uint32_t start = simpleCandidates[i];
                
                // Count consecutive patterns within 1KB
                for (size_t j = i + 1; j < simpleCandidates.size() && 
                     simpleCandidates[j] - start < 1024; j++) {
                    count++;
                }
                
                if (count > bestCount) {
                    bestCount = count;
                    bestStart = start;
                }
            }
            
            if (bestCount >= 5) { // If we found a cluster of at least 5 patterns
                setjmpAddress = baseAddress + bestStart;
                fmt::println("setjmp_address = 0x{:X}  # Found in C runtime area with {} similar patterns", setjmpAddress, bestCount);
            }
        }
    }

    // If still not found, provide guidance
    if (setjmpAddress == UINT32_MAX) {
        fmt::println("# setjmp_address = NOT_FOUND  # Look for functions that save registers and return 0");
    }
    if (longjmpAddress == UINT32_MAX) {
        fmt::println("# longjmp_address = NOT_FOUND  # Look for functions that restore registers and jump");
    }
}

void ReadTable(Image& image, SwitchTable& table)
{
    uint32_t pOffset;
    ppc_insn insn;
    auto* code = (uint32_t*)image.Find(table.base);
    ppc::Disassemble(code, table.base, insn);
    pOffset = insn.operands[1] << 16;

    ppc::Disassemble(code + 1, table.base + 4, insn);
    pOffset += insn.operands[2];

    if (table.type == SWITCH_ABSOLUTE)
    {
        const auto* offsets = (be<uint32_t>*)image.Find(pOffset);
        for (size_t i = 0; i < table.labels.size(); i++)
        {
            table.labels[i] = offsets[i];
        }
    }
    else if (table.type == SWITCH_COMPUTED)
    {
        uint32_t base;
        uint32_t shift;
        const auto* offsets = (uint8_t*)image.Find(pOffset);

        ppc::Disassemble(code + 4, table.base + 0x10, insn);
        base = insn.operands[1] << 16;

        ppc::Disassemble(code + 5, table.base + 0x14, insn);
        base += insn.operands[2];

        ppc::Disassemble(code + 3, table.base + 0x0C, insn);
        shift = insn.operands[2];

        for (size_t i = 0; i < table.labels.size(); i++)
        {
            table.labels[i] = base + (offsets[i] << shift);
        }
    }
    else if (table.type == SWITCH_BYTEOFFSET || table.type == SWITCH_SHORTOFFSET)
    {
        if (table.type == SWITCH_BYTEOFFSET)
        {
            const auto* offsets = (uint8_t*)image.Find(pOffset);
            uint32_t base;

            ppc::Disassemble(code + 3, table.base + 0x0C, insn);
            base = insn.operands[1] << 16;

            ppc::Disassemble(code + 4, table.base + 0x10, insn);
            base += insn.operands[2];

            for (size_t i = 0; i < table.labels.size(); i++)
            {
                table.labels[i] = base + offsets[i];
            }
        }
        else if (table.type == SWITCH_SHORTOFFSET)
        {
            const auto* offsets = (be<uint16_t>*)image.Find(pOffset);
            uint32_t base;

            ppc::Disassemble(code + 4, table.base + 0x10, insn);
            base = insn.operands[1] << 16;

            ppc::Disassemble(code + 5, table.base + 0x14, insn);
            base += insn.operands[2];

            for (size_t i = 0; i < table.labels.size(); i++)
            {
                table.labels[i] = base + offsets[i];
            }
        }
    }
    else
    {
        assert(false);
    }
}

void ScanTable(const uint32_t* code, size_t base, SwitchTable& table)
{
    ppc_insn insn;
    uint32_t cr{ (uint32_t)-1 };
    for (int i = 0; i < 32; i++)
    {
        ppc::Disassemble(&code[-i], base - (4 * i), insn);
        if (insn.opcode == nullptr)
        {
            continue;
        }

        if (cr == -1 && (insn.opcode->id == PPC_INST_BGT || insn.opcode->id == PPC_INST_BGTLR || insn.opcode->id == PPC_INST_BLE || insn.opcode->id == PPC_INST_BLELR))
        {
            cr = insn.operands[0];
            if (insn.opcode->operands[1] != 0)
            {
                table.defaultLabel = insn.operands[1];
            }
        }
        else if (cr != -1)
        {
            if (insn.opcode->id == PPC_INST_CMPLWI && insn.operands[0] == cr)
            {
                table.r = insn.operands[1];
                table.labels.resize(insn.operands[2] + 1);
                table.base = base;
                break;
            }
        }
    }
}

void MakeMask(const uint32_t* instructions, size_t count)
{
    ppc_insn insn;
    for (size_t i = 0; i < count; i++)
    {
        ppc::Disassemble(&instructions[i], 0, insn);
        fmt::println("0x{:X}, // {}", ByteSwap(insn.opcode->opcode | (insn.instruction & insn.opcode->mask)), insn.opcode->name);
    }
}

void* SearchMask(const void* source, const uint32_t* compare, size_t compareCount, size_t size)
{
    assert(size % 4 == 0);
    uint32_t* src = (uint32_t*)source;
    size_t count = size / 4;
    ppc_insn insn;

    for (size_t i = 0; i < count; i++)
    {
        size_t c = 0;
        for (c = 0; c < compareCount; c++)
        {
            ppc::Disassemble(&src[i + c], 0, insn);
            if (insn.opcode == nullptr || insn.opcode->id != compare[c])
            {
                break;
            }
        }

        if (c == compareCount)
        {
            return &src[i];
        }
    }

    return nullptr;
}

static std::string out;

template<class... Args>
static void println(fmt::format_string<Args...> fmt, Args&&... args)
{
    fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
    out += '\n';
};

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("Usage: XenonAnalyse [input XEX file path] [output TOML config file path] [optional: output directory path] [optional: symbol file path]\n");
        printf("  symbol file: JSON file with extracted PDB symbols (from extract_symbols.py)\n");
        return EXIT_SUCCESS;
    }

    const auto file = LoadFile(argv[1]);
    fmt::println("File loaded, size: {}", file.size());
    
    auto image = Image::ParseImage(file.data(), file.size());
    fmt::println("Image parsed, size: {}, sections: {}", image.size, image.sections.size());

    // Load symbol information if provided
    bool hasSymbols = false;
    if (argc >= 5) {
        std::string symbolFile = argv[4];
        if (InitializeSymbolResolver(symbolFile)) {
            hasSymbols = true;
            fmt::println("✅ Loaded {} symbols from: {}", g_symbolResolver->GetSymbolCount(), symbolFile);
        } else {
            fmt::println("⚠️  Failed to load symbols from: {}", symbolFile);
        }
    } else {
        fmt::println("ℹ️  No symbol file provided - using generic function names");
    }

    // Store runtime function addresses for TOML generation
    std::map<std::string, uint32_t> runtimeFunctions;
    
    // Capture runtime function search results
    uint32_t baseAddress = UINT32_MAX;
    for (const auto& section : image.sections) {
        if (section.name == ".text") {
            baseAddress = section.base;
            if (baseAddress != UINT32_MAX) {
                runtimeFunctions["restgprlr_14_address"] = BytePatternSearch(section.data, section.size, baseAddress, RESTGPRLR_14, sizeof(RESTGPRLR_14));
                runtimeFunctions["savegprlr_14_address"] = BytePatternSearch(section.data, section.size, baseAddress, SAVEGPRLR_14, sizeof(SAVEGPRLR_14));
                runtimeFunctions["restfpr_14_address"] = BytePatternSearch(section.data, section.size, baseAddress, RESTFPR_14, sizeof(RESTFPR_14));
                runtimeFunctions["savefpr_14_address"] = BytePatternSearch(section.data, section.size, baseAddress, SAVEFPR_14, sizeof(SAVEFPR_14));
                runtimeFunctions["restvmx_14_address"] = BytePatternSearch(section.data, section.size, baseAddress, RESTVMX_14, sizeof(RESTVMX_14));
                runtimeFunctions["savevmx_14_address"] = BytePatternSearch(section.data, section.size, baseAddress, SAVEVMX_14, sizeof(SAVEVMX_14));
                runtimeFunctions["restvmx_64_address"] = BytePatternSearch(section.data, section.size, baseAddress, RESTVMX_64, sizeof(RESTVMX_64));
                runtimeFunctions["savevmx_64_address"] = BytePatternSearch(section.data, section.size, baseAddress, SAVEVMX_64, sizeof(SAVEVMX_64));
                break;
            }
        }
    }

    RegisterFunctionsSearch(image);
    
    // Capture setjmp/longjmp search results
    uint32_t setjmpAddress = UINT32_MAX;
    uint32_t longjmpAddress = UINT32_MAX;
    
    // Run setjmp/longjmp detection and capture results
    const uint8_t* data = nullptr;
    uint32_t dataSize = 0;
    for (const auto& section : image.sections) {
        if (section.name == ".text") {
            data = section.data;
            dataSize = section.size;
            break;
        }
    }
    
    if (data != nullptr && baseAddress != UINT32_MAX) {
        // setjmp detection
        static const uint8_t SETJMP_PATTERN[] = { 0x7c, 0x08, 0x02, 0xa6, 0x7c, 0x80, 0x00, 0x26, 0xd9, 0xc3, 0x00, 0x00 };
        setjmpAddress = BytePatternSearch(const_cast<uint8_t*>(data), dataSize, baseAddress, SETJMP_PATTERN, sizeof(SETJMP_PATTERN));
        
        if (setjmpAddress != UINT32_MAX) {
            runtimeFunctions["setjmp_address"] = setjmpAddress;
        }
    }
    
    LongJmpSetJmpSearch(image);

    auto printTable = [&](const SwitchTable& table)
        {
            println("[[switch]]");
            println("base = 0x{:X}", table.base);
            println("r = {}", table.r);
            println("default = 0x{:X}", table.defaultLabel);
            println("labels = [");
            for (const auto& label : table.labels)
            {
                println("    0x{:X},", label);
            }

            println("]");
            println("");
        };

    std::vector<SwitchTable> switches{};

    // Generate complete TOML configuration
    std::string inputPath = argv[1];
    std::string outputDir = argc > 3 ? argv[3] : "./output";
    
    println("# Generated by XenonAnalyse - Complete Configuration");
    println("# XEX File: {}", inputPath);
    println("");
    println("[main]");
    println("file_path = \"{}\"", inputPath);
    println("out_directory_path = \"{}\"", outputDir);
    println("");
    println("# Runtime library functions (auto-detected)");
    
    for (const auto& [name, address] : runtimeFunctions) {
        if (address != UINT32_MAX) {
            println("{} = 0x{:X}", name, address);
        } else {
            println("# {} = NOT_FOUND", name);
        }
    }
    
    println("");
    println("# Optimization settings (conservative defaults)");
    println("skip_lr = false");
    println("skip_msr = false");
    println("ctr_as_local = false");
    println("xer_as_local = false");
    println("reserved_as_local = false");
    println("cr_as_local = false");
    println("non_argument_as_local = false");
    println("non_volatile_as_local = false");
    println("");
    println("# Switch tables (auto-detected)");

    auto scanPattern = [&](uint32_t* pattern, size_t count, size_t type)
        {
            for (const auto& section : image.sections)
            {
                if (!(section.flags & SectionFlags_Code))
                {
                    continue;
                }

                size_t base = section.base;
                uint8_t* data = section.data;
                uint8_t* dataStart = section.data;
                uint8_t* dataEnd = section.data + section.size;
                while (data < dataEnd && data != nullptr)
                {
                    data = (uint8_t*)SearchMask(data, pattern, count, dataEnd - data);

                    if (data != nullptr)
                    {
                        SwitchTable table{};
                        table.type = type;
                        ScanTable((uint32_t*)data, base + (data - dataStart), table);

                        // fmt::println("{:X} ; jmptable - {}", base + (data - dataStart), table.labels.size());
                        if (table.base != 0)
                        {
                            ReadTable(image, table);
                            printTable(table);
                            switches.emplace_back(std::move(table));
                        }

                        data += 4;
                    }
                    continue;
                }
            }
        };

    uint32_t absoluteSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_RLWINM,
        PPC_INST_LWZX,
        PPC_INST_MTCTR,
        PPC_INST_BCTR,
    };

    uint32_t computedSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_LBZX,
        PPC_INST_RLWINM,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    uint32_t offsetSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_LBZX,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    uint32_t wordOffsetSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_RLWINM,
        PPC_INST_LHZX,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    println("# ---- ABSOLUTE JUMPTABLE ----");
    scanPattern(absoluteSwitch, std::size(absoluteSwitch), SWITCH_ABSOLUTE);

    println("# ---- COMPUTED JUMPTABLE ----");
    scanPattern(computedSwitch, std::size(computedSwitch), SWITCH_COMPUTED);

    scanPattern(offsetSwitch, std::size(offsetSwitch), SWITCH_BYTEOFFSET);
    scanPattern(wordOffsetSwitch, std::size(wordOffsetSwitch), SWITCH_SHORTOFFSET);
    
    // Add binary structure information
    println("");
    println("# Binary Structure Information");
    println("[binary_info]");
    println("file_size = {}", std::filesystem::file_size(inputPath));
    println("image_size = {}", image.size);
    println("section_count = {}", image.sections.size());
    println("");
    
    // Add section information
    println("# Section Layout");
    for (const auto& section : image.sections) {
        // Clean section name for TOML compatibility
        std::string cleanName = section.name;
        std::replace(cleanName.begin(), cleanName.end(), '\f', ' '); // Form feed
        std::replace(cleanName.begin(), cleanName.end(), '\v', ' '); // Vertical tab
        std::replace(cleanName.begin(), cleanName.end(), '\r', ' '); // Carriage return
        std::replace(cleanName.begin(), cleanName.end(), '\n', ' '); // Newline
        
        println("# {} - Base: 0x{:X}, Size: 0x{:X}, Flags: 0x{:X}", 
                cleanName, section.base, section.size, static_cast<uint32_t>(section.flags));
    }
    println("");

    // Add debug information configuration
    if (hasSymbols && g_symbolResolver) {
        println("# Debug Information Configuration");
        println("[debug_info]");
        if (argc > 4) {
            println("symbols_file = \"{}\"", argv[4]);
        }
        println("symbol_count = {}", g_symbolResolver->GetSymbolCount());
        println("");

        println("# Symbol Database Information");
        println("# Use the symbols_file for comprehensive symbol lookup");
        println("# Symbols can be searched by pattern, type, or name");
        println("# Total symbols available: {}", g_symbolResolver->GetSymbolCount());
        println("");
    }
    
    println("# Advanced Configuration Examples (uncomment and modify as needed)");
    println("");
    println("# Specific function targeting:");
    if (hasSymbols) {
        println("# [[functions]]");
        println("# address = 0x82000000  # Use XEX analysis to find actual addresses");
        println("# size = 0x1000");
        println("# # Example: Target a specific game function");
        println("# # Look for symbols like 'Player::Update' or 'GameMain::Initialize'");
    } else {
        println("# [[functions]]");
        println("# address = 0x82000000");
        println("# size = 0x1000");
    }
    println("");
    println("# Invalid instruction detection (for padding/exception handlers):");
    println("# [[invalid_instructions]]");
    println("# data = 0x82000000");
    println("# size = 4");
    println("");
    println("# Mid-assembly hooks (advanced debugging/modification):");
    println("# [[midasm_hook]]");
    println("# address = 0x82000000");
    println("# name = \"debug_hook\"");
    println("# registers = [\"r3\", \"r4\"]");
    println("# return = false");
    println("# after_instruction = false");

    std::ofstream f(argv[2]);
    f.write(out.data(), out.size());

    return EXIT_SUCCESS;
}
