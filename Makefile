BASENAME=PyPkcs11

CFLAGS='-O0 -w'

CYTHON_MODULE_LIB=$(BASENAME).cpython-*.so

all: $(CYTHON_MODULE_LIB)

$(CYTHON_MODULE_LIB): pysetup.py $(BASENAME).pyx
	BASENAME=$(BASENAME) python3 pysetup.py build_ext --inplace

test: $(CYTHON_MODULE_LIB)
	./$(BASENAME)_test.py

clean:
	rm -rf $(CYTHON_MODULE_LIB) $(BASENAME).c build *.o
