# pyba2: Python tools for Beyond Architecture 2 firmware analysis

The project is intended for use with [radare2](https://www.radare.org/r/), but is structured in such a way that it should be useful in other Python-based environments (such as gdb).

# Usage

1. Clone the project: `git clone https://github.com/alephsecurity/pyba2`
2. Change into its directory: `cd pyba2`
3. Make sure radare2 Python plugin is installed: `r2pm -i lang-python`
4. Run radare2 with `-I ba2r2.py`: `r2 -I ba2r2.py jn516x_ota_firmware_file.bin`
5. ...
6. Profit!

# Requirements

## Python 3.6

This project uses some modern features (e.g., f-strings) not available in prior Python versions. If using an older version of Python is a necessity, you're welcome to fork and change the project as needed.

## bitstring

This isn't actually a requirement. Using virtual environments with radare2 plugins is tricky, so we just copied the module into our repository. However, they deserve the credit, so check [bitstring](https://pythonhosted.org/bitstring/index.html)!

## radare2

To use the plugin with radare2, be sure to install the `lang-python` plugin first: `r2pm -i lang-python`.

# Contributing

The project is in development, and contributions are welcome! Go ahead and open issues (hopefully you don't find any :)), and use pull requests to improve the project!
