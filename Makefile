zydis_fuzzer: zydis_fuzzer.cc
	gcc $< -o $@ -O3 -lZydis

clean:
	rm -f zydis_fuzzer
