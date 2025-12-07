#include "symbol_resolver.h"
#include <fstream>
#include <algorithm>
#include <cctype>
#include <regex>
#include <fmt/core.h>

// JSON parsing - simple implementation for our specific format
#include <sstream>

std::unique_ptr<SymbolResolver> g_symbolResolver = nullptr;

bool SymbolResolver::LoadSymbols(const std::string& symbolFile) {
    std::ifstream file(symbolFile);
    if (!file.is_open()) {
        return false;
    }

    // Read entire file
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();

    // Simple JSON parsing for our specific format
    // Expected format: [{"name": "...", "type": "...", "class": "...", "method": "..."}, ...]
    
    symbols_.clear();
    
    // Find all symbol objects - improved parsing
    size_t pos = 0;
    while ((pos = content.find("{", pos)) != std::string::npos) {
        // Find the matching closing brace
        size_t braceCount = 1;
        size_t end = pos + 1;
        while (end < content.length() && braceCount > 0) {
            if (content[end] == '{') braceCount++;
            else if (content[end] == '}') braceCount--;
            end++;
        }
        
        if (braceCount == 0) {
            std::string symbolJson = content.substr(pos, end - pos);
            
            SymbolInfo symbol;
            
            // Extract name - look for "name": "value"
            auto namePos = symbolJson.find("\"name\":");
            if (namePos != std::string::npos) {
                auto nameStart = symbolJson.find("\"", namePos + 7);
                if (nameStart != std::string::npos) {
                    nameStart++; // Skip opening quote
                    auto nameEnd = symbolJson.find("\"", nameStart);
                    if (nameEnd != std::string::npos) {
                        symbol.name = symbolJson.substr(nameStart, nameEnd - nameStart);
                    }
                }
            }
            
            // Extract type
            auto typePos = symbolJson.find("\"type\":");
            if (typePos != std::string::npos) {
                auto typeStart = symbolJson.find("\"", typePos + 7);
                if (typeStart != std::string::npos) {
                    typeStart++; // Skip opening quote
                    auto typeEnd = symbolJson.find("\"", typeStart);
                    if (typeEnd != std::string::npos) {
                        symbol.type = symbolJson.substr(typeStart, typeEnd - typeStart);
                    }
                }
            }
            
            // Extract class (for methods)
            auto classPos = symbolJson.find("\"class\":");
            if (classPos != std::string::npos) {
                auto classStart = symbolJson.find("\"", classPos + 8);
                if (classStart != std::string::npos) {
                    classStart++; // Skip opening quote
                    auto classEnd = symbolJson.find("\"", classStart);
                    if (classEnd != std::string::npos) {
                        symbol.className = symbolJson.substr(classStart, classEnd - classStart);
                    }
                }
            }
            
            // Extract method (for methods)
            auto methodPos = symbolJson.find("\"method\":");
            if (methodPos != std::string::npos) {
                auto methodStart = symbolJson.find("\"", methodPos + 9);
                if (methodStart != std::string::npos) {
                    methodStart++; // Skip opening quote
                    auto methodEnd = symbolJson.find("\"", methodStart);
                    if (methodEnd != std::string::npos) {
                        symbol.methodName = symbolJson.substr(methodStart, methodEnd - methodStart);
                    }
                }
            }
            
            if (!symbol.name.empty()) {
                symbols_.push_back(symbol);
            }
        }
        
        pos = end;
    }
    
    BuildAddressMap();
    return !symbols_.empty();
}

std::string SymbolResolver::ResolveAddress(uint32_t address) const {
    auto it = addressToSymbol_.find(address);
    if (it != addressToSymbol_.end()) {
        return symbols_[it->second].name;
    }
    return "";
}

std::vector<SymbolInfo> SymbolResolver::FindSymbolsByPattern(const std::string& pattern) const {
    std::vector<SymbolInfo> matches;
    std::string lowerPattern = ToLower(pattern);
    
    for (const auto& symbol : symbols_) {
        std::string lowerName = ToLower(symbol.name);
        if (lowerName.find(lowerPattern) != std::string::npos) {
            matches.push_back(symbol);
        }
    }
    
    return matches;
}

std::string SymbolResolver::SanitizeFunctionName(const std::string& symbol) {
    std::string result = symbol;
    
    // Replace invalid characters with underscores
    std::regex invalidChars("[^a-zA-Z0-9_]");
    result = std::regex_replace(result, invalidChars, "_");
    
    // Ensure it starts with letter or underscore
    if (!result.empty() && std::isdigit(result[0])) {
        result = "_" + result;
    }
    
    // Remove consecutive underscores
    std::regex multipleUnderscores("_{2,}");
    result = std::regex_replace(result, multipleUnderscores, "_");
    
    // Remove trailing underscores
    while (!result.empty() && result.back() == '_') {
        result.pop_back();
    }
    
    // Ensure it's not empty
    if (result.empty()) {
        result = "unknown_function";
    }
    
    return result;
}

std::string SymbolResolver::GetFunctionName(uint32_t address) const {
    std::string symbolName = ResolveAddress(address);
    if (!symbolName.empty()) {
        return SanitizeFunctionName(symbolName);
    }
    
    // Fallback to traditional naming
    return fmt::format("sub_{:08X}", address);
}

void SymbolResolver::BuildAddressMap() {
    addressToSymbol_.clear();
    
    // For now, we don't have address information in the PDB symbols
    // This would need to be enhanced with actual address mapping
    // from the XEX file or additional debug information
    
    // Future enhancement: correlate with XEX function addresses
}

std::string SymbolResolver::ToLower(const std::string& str) const {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

bool InitializeSymbolResolver(const std::string& symbolFile) {
    g_symbolResolver = std::make_unique<SymbolResolver>();
    return g_symbolResolver->LoadSymbols(symbolFile);
}