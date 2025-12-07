#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <optional>

/**
 * @brief Symbol information extracted from PDB files
 */
struct SymbolInfo {
    std::string name;
    std::string type;  // "function", "method", "namespaced_function"
    std::string className;  // For methods
    std::string methodName; // For methods
    uint32_t address = 0;   // Will be populated if address mapping is available
    uint32_t size = 0;      // Function size if available
};

/**
 * @brief Resolves function addresses to symbol names using PDB-extracted symbols
 */
class SymbolResolver {
public:
    /**
     * @brief Load symbols from JSON file created by extract_symbols.py
     * @param symbolFile Path to JSON file containing extracted symbols
     * @return true if symbols loaded successfully
     */
    bool LoadSymbols(const std::string& symbolFile);

    /**
     * @brief Find symbol name for a given address
     * @param address Function address
     * @return Symbol name if found, empty string otherwise
     */
    std::string ResolveAddress(uint32_t address) const;

    /**
     * @brief Find symbol by name pattern
     * @param pattern Pattern to search for (case-insensitive)
     * @return Vector of matching symbols
     */
    std::vector<SymbolInfo> FindSymbolsByPattern(const std::string& pattern) const;

    /**
     * @brief Get all loaded symbols
     * @return Vector of all symbols
     */
    const std::vector<SymbolInfo>& GetAllSymbols() const { return symbols_; }

    /**
     * @brief Get symbol count
     * @return Number of loaded symbols
     */
    size_t GetSymbolCount() const { return symbols_.size(); }

    /**
     * @brief Create a sanitized C++ function name from symbol
     * @param symbol Original symbol name
     * @return Valid C++ identifier
     */
    static std::string SanitizeFunctionName(const std::string& symbol);

    /**
     * @brief Generate function name for address (with fallback)
     * @param address Function address
     * @return Symbol name if available, otherwise sub_XXXXXXXX format
     */
    std::string GetFunctionName(uint32_t address) const;

    /**
     * @brief Check if symbols are loaded
     * @return true if symbols are available
     */
    bool HasSymbols() const { return !symbols_.empty(); }

private:
    std::vector<SymbolInfo> symbols_;
    std::unordered_map<uint32_t, size_t> addressToSymbol_;  // address -> index in symbols_
    
    void BuildAddressMap();
    std::string ToLower(const std::string& str) const;
};

/**
 * @brief Global symbol resolver instance
 */
extern std::unique_ptr<SymbolResolver> g_symbolResolver;

/**
 * @brief Initialize global symbol resolver
 * @param symbolFile Path to symbol file
 * @return true if initialized successfully
 */
bool InitializeSymbolResolver(const std::string& symbolFile);