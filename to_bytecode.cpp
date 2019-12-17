#include <iostream>
#include <fstream>
#include "js.h"

int main(int argc, char** argv)
{
    if ( argc != 3 ) {
        std::cout << "Usage: " << argv[0] << " <in javascript> <out bytecode>" << std::endl;
        return 1;
    }

    const auto bytecode = JS::CompileJavascript(argv[1]);

    std::fstream bcfp;
    bcfp.open(argv[2], std::ios::app | std::ios::binary);
    bcfp.write(reinterpret_cast<const char*>(bytecode.data()), bytecode.size());

    return 0;
}
