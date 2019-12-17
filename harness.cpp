#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include "js.h"

JS* js = nullptr;

extern "C" int LLVMFuzzerInitialize(int* argc, char*** _argv) {
    ::js = new JS();

    char** argv = *_argv;
    std::string javascriptFilename;

    for (int i = 0; i < *argc; i++) {
        const std::string curArg = std::string(argv[i]);
        if ( curArg.rfind("--js=", 0) == 0 ) {
            javascriptFilename = std::string(&curArg[5]);
        }
    }

    if ( javascriptFilename.empty() ) {
        std::cout << "Specify JavaScript with --js=<filename>" << std::endl;
        exit(1);
    }

    ::js->SetBytecode(JS::CompileJavascript(javascriptFilename));

    ::js->SetMemoryLimit(1024*1024*10);

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    js->Run(data, size);
    return 0;
}
