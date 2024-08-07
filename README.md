# API hashes used by malware
Malware actors usually use API hashing to resolve API functions' addresses in a runtime. This repository contains a script for generating various hashes of the most popular APIs. API names list can be found in `api-list.txt` file, use it for your own purposes, if needed.

## Further development
You are free to add new algorithms into `algorithms.py` file. Just run `main.py` to re-generate API hashes list.

## Known hashing algorithms used by malware:
* BZip2 CRC32 (lowercase): Formbook/Xloader 