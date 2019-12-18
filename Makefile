all : fuzzer to_bytecode

js.o : js.cpp js.h
	clang++ -std=c++17 -g -I quickjs/ -fsanitize=fuzzer-no-link js.cpp -c -o js.o

quickjs/libquickjs.a : 
	cd quickjs && make libquickjs.a

fuzzer : harness.cpp js.o quickjs/libquickjs.a
	clang++ -std=c++17 -fsanitize=fuzzer harness.cpp js.o quickjs/libquickjs.a -o fuzzer

to_bytecode : to_bytecode.cpp js.o
	clang++ -std=c++17 -fsanitize=fuzzer-no-link to_bytecode.cpp js.o quickjs/libquickjs.a -ldl -lm -o to_bytecode
