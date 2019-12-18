# libfuzzer-js

libFuzzer-based JavaScript fuzzing using Bellard's [QuickJS](https://bellard.org/quickjs/).

## Building

You need a recent version of libFuzzer for optimal coverage capturing.

Run this from any path:

```sh
svn co https://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer Fuzzer
cd Fuzzer
./build.sh
export LIBFUZZER_A_PATH=$(realpath libFuzzer.a)
```

In this project's root directory, type:

```sh
make
```

## Writing fuzzers

Input is supplied through the ```FuzzerInput``` variable, which is a ```Uint8Array```.

## API

An API suited for embedding in a larger application (e.g. a differential fuzzer) is defined in ```JS.cpp/h```.

## Running

```sh
./jsfuzzer --js=<javascript file>
```

## Module support

There is currently no support for modules. To use multiple JavaScript files, concatenate all the files you need for now.

E.g.:

```sh
cat foo.js bar.js >file.js
./jsfuzzer --js=file.js
```

## Notes

This is a work in progress. Capabilities and internal structure may change without prior notice.
