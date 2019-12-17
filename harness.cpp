#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include "js.h"

JS* js = nullptr;

extern "C" int LLVMFuzzerInitialize(int* argc, char*** _argv) {
    ::js = new JS();

    char** argv = *_argv;
    bool haveCode = false;

    for (int i = 0; i < *argc; i++) {
        const std::string curArg = std::string(argv[i]);
        if ( curArg.rfind("--js=", 0) == 0 ) {
            const auto fn = std::string(&curArg[5]);
            ::js->SetBytecode(JS::CompileJavascript(fn));
            haveCode = true;
        } else if ( curArg.rfind("--bc=", 0) == 0 ) {
            const auto fn = std::string(&curArg[5]);
            const auto bc = JS::LoadFile(fn);
            ::js->SetBytecode(bc);
            haveCode = true;
        }
    }

    if ( haveCode == false ) {
        std::cout << "Specify JavaScript with --js=<filename> or QuickJS bytecode with --bc=<filename>" << std::endl;
        exit(1);
    }

    ::js->SetMemoryLimit(1024*1024*10);

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    js->Run(data, size);
    return 0;
}
