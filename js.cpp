#include <iostream>
#include <fstream>
#include "js.h"
extern "C" {
    #include <quickjs-libc.h>
}

JS::JS(void) :
    memoryLimit(0) {
}

void JS::SetBytecode(const std::vector<char>& bytecode) {
    SetBytecode(std::vector<uint8_t>(
                (uint8_t*)bytecode.data(),
                (uint8_t*)(bytecode.data() + bytecode.size())));
}
        
void JS::SetBytecode(const std::vector<uint8_t>& bytecode) {
    this->bytecode = bytecode;
}

void JS::SetMemoryLimit(const size_t limit) {
    memoryLimit = limit;
}

std::vector<char> JS::LoadFile(const std::string& fn) {
    std::vector<char> buffer;
    std::ifstream file(fn, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    if ( size <= 0 ) {
        throw std::runtime_error("LoadFile: Load error");
    }
    file.seekg(0, std::ios::beg);

    buffer.resize(size);
    if (!file.read(buffer.data(), size)) {
        throw std::runtime_error("LoadFile: Read error");
    }

    return buffer;
}

std::vector<uint8_t> JS::CompileJavascript(const std::string& javascriptFilename) {
    std::vector<char> buffer;

    try {
        buffer = LoadFile(javascriptFilename);
    } catch ( std::exception ) {
        std::cout << "Cannot read JavaScript file" << std::endl;
        exit(1);
    }

    {
        std::vector<uint8_t> ret;
        JSRuntime* rt = JS_NewRuntime();
        JSContext* ctx = JS_NewContextRaw(rt);

        JS_AddIntrinsicEval(ctx);
        JS_AddIntrinsicRegExpCompiler(ctx);

        JSValue obj;
        
        /* Parse */
        {
            obj = JS_Eval(
                    ctx,
                    buffer.data(),
                    buffer.size(),
                    javascriptFilename.c_str(),
                    JS_EVAL_FLAG_COMPILE_ONLY | JS_EVAL_TYPE_GLOBAL | JS_EVAL_TYPE_MODULE);
            if (JS_IsException(obj)) {
                goto err_compile;
            }
        }

        /* To bytecode */
        {
            size_t out_buf_len;
            uint8_t* out_buf = JS_WriteObject(ctx, &out_buf_len, obj, JS_WRITE_OBJ_BYTECODE);
            if ( !out_buf ) {
                goto err_compile;
            }

            ret = std::vector<uint8_t>(out_buf, out_buf + out_buf_len);

            js_free(ctx, out_buf);
        }

        JS_FreeValue(ctx, obj);

        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);

        return ret;

err_compile:
        js_std_dump_error(ctx);
        std::cout << "Cannot compile JavaScript file" << std::endl;
        exit(1);
    }
}

void JS::Run(const uint8_t* data, const size_t size) {
    JSRuntime* rt = nullptr;
    JSContext* ctx = nullptr;

    if ( bytecode.empty() ) {
        std::cout << "No bytecode defined" << std::endl;
        exit(1);
    }

    /* Instantiate */
    {
        rt = JS_NewRuntime();
        ctx = JS_NewContext(rt);
    }

    /* Configure */
    {
        if ( memoryLimit ) {
            /* noret */ JS_SetMemoryLimit(rt, memoryLimit);
        }
        /* noret */ JS_SetGCThreshold(rt, -1);
        /* noret */ js_std_add_helpers(ctx, 0, nullptr);
    }

    /* Specify input */
    {
        const std::string scriptHeader = "var FuzzerInput = new Uint8Array([";
        std::string scriptBody = "";
        const std::string scriptFooter = "]);";

        for (size_t i = 0; i < size; i++) {
            scriptBody += std::to_string(data[i]);
            if ( i + 1 != size ) {
                scriptBody += ",";
            }
        }

        const std::string script = scriptHeader + scriptBody + scriptFooter;
        JSValue val = JS_Eval(ctx, script.data(), script.size(), "<none>", JS_EVAL_TYPE_GLOBAL);
        if (JS_IsException(val)) {
            js_std_dump_error(ctx);
            exit(1);
        }
    }

    /* Run */
    {
        /* noret */ js_std_eval_binary(ctx, bytecode.data(), bytecode.size(), 0);
        /* noret */ js_std_loop(ctx);
    }

    /* Free */
    {
        /* noret */ JS_FreeContext(ctx);
        /* noret */ JS_FreeRuntime(rt);
    }
}
