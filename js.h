#pragma once

#include <vector>
#include <string>

class JS {
    private:
        std::vector<uint8_t> bytecode;
        size_t memoryLimit;
    public:
        JS(void);
        static std::vector<uint8_t> CompileJavascript(const std::string& javascriptFilename);
        void SetBytecode(const std::vector<uint8_t>& bytecode);
        void SetMemoryLimit(const size_t limit);
        void Run(const uint8_t* data, const size_t size);
};
