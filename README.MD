A Python script to decode RenPy `persistent` files and convert their contents to JSON. It is designed to handle various compression formats and legacy Python 2 pickle protocols without requiring the Ren'Py engine.

This script addresses the challenge of reading Ren'Py persistent files, which are Python pickles dependent on internal Ren'Py classes and often use legacy formats.

It operates by first installing lightweight stub modules to emulate the Ren'Py environment. It then employs a multi-stage pipeline to decompress (zlib, gzip, etc.) and robustly unpickle the data, handling common encoding and formatting errors. The recovered Python object is then serialized to a clean JSON format.

- No external dependencies (uses only the Python standard library).
- Handles multiple compression formats (zlib, gzip, bz2, lzma).
- Compatible with Python 2 legacy pickle formats.
- Recovers data from malformed or concatenated files. (maybe)

### Usage

1. Place the persistent file in the script's directory.
2. Execute the script from your terminal:
```cmd
python main.py
```
3. The output will be saved to the file specified by the `OUTPUT_JSON` variable.

> Note: python version tested was 3.14.2

### Configuration

Input and output paths can be configured by modifying the global variables at the top of the script:

```python
PERSISTENT_PATH = pathlib.Path("persistent")
OUTPUT_JSON = pathlib.Path("persistent-fran.json")
```
