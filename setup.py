from setuptools import setup, Extension, find_packages
from Cython.Build import cythonize
import os

# Define extension modules:
extensions = [
    Extension(
        name="pypkcs11.PyPkcs11",
        sources=[os.path.join("pypkcs11", "PyPkcs11.pyx")],
        # Optionally set include_dirs, library_dirs, libraries, etc.
    ),
]

# Use cythonize to compile the .pyx files:
setup(
    name="pypkcs11",
    ext_modules=cythonize(extensions, compiler_directives={"language_level": "3"}),
    packages=find_packages(),
    include_package_data=True,  # if you’re using MANIFEST.in for sdist
    exclude_package_data={ '': ['*.c', '*.pyx'] },
    entry_points={
        'console_scripts': [
            'pypkcs11-utility=pypkcs11.PyPkcs11Utility:main'
        ]
    }
)
