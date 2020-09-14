all : jsfuzzer to_bytecode

js.o : js.cpp js.h
	$(CXX) -std=c++17 -g -I quickjs/ -fsanitize=fuzzer-no-link js.cpp -c -o js.o

quickjs/libquickjs.a : 
	cd quickjs && make libquickjs.a

jsfuzzer : harness.cpp js.o quickjs/libquickjs.a
	test $(LIBFUZZER_A_PATH)
	$(CXX) -std=c++17 harness.cpp js.o quickjs/libquickjs.a $(LIBFUZZER_A_PATH) -ldl -lpthread -o jsfuzzer

to_bytecode : to_bytecode.cpp js.o
	$(CXX) -std=c++17 -fsanitize=fuzzer-no-link to_bytecode.cpp js.o quickjs/libquickjs.a -ldl -lm -o to_bytecode
