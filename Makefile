BASENAME=PyPkcs11
SRC=pypkcs11

CFLAGS='-ggdb -O0 -w'

CYTHON_MODULE_LIB=$(BASENAME).cpython-*.so

wheel: LICENSE MANIFEST.in pyproject.toml README.md setup.cfg  setup.py $(SRC)/*.py $(SRC)/*.pyx
	python3.11 -m build

solib: $(CYTHON_MODULE_LIB)

$(CYTHON_MODULE_LIB): setup.py $(SRC)/$(BASENAME).pyx
	CFLAGS=$(CFLAGS) BASENAME=$(BASENAME) python3.11 setup.py build_ext --inplace

test: $(CYTHON_MODULE_LIB)
	./$(BASENAME)_test.py

clean:
	rm -rf $(SRC)/$(BASENAME).c $(SRC)/*.o $(SRC)/$(CYTHON_MODULE_LIB) build
