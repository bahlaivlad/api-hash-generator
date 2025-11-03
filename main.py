import zlib
from collections.abc import Callable
from os import listdir, path
from typing import Any

import pefile

from algorithms import *

API_NAMES_LIST = "api-list.txt"
CSV_HEADER = "HASH,HASH_W_LEADING_ZEROS,API_NAME"
LINE_SEPARATOR = "\n"

MODIFIER_FUNC_STUB = lambda _: _
MODIFIERS = (
    ("", MODIFIER_FUNC_STUB),
    ("_lowercase", lambda x: x.lower()),
    ("_uppercase", lambda x: x.upper()),
)
ALGORITHMS = (
    ("bzip_crc32", zlib.crc32),
    ("bzip2_crc32", bzip2_crc32),
    ("backupwin_trojan", BackupWinTrojan),
)


def read_api_names_list() -> list[str]:
    """
    Reads a list of API names from `API_NAMES_LIST` file.
    :return: list of API names.
    """
    with open(API_NAMES_LIST, "r") as f:
        api_names = f.read().splitlines(keepends=False)
    return api_names


def dump_api_names_list(apis: set[str]) -> None:
    """
    Dumps a list of API names to the `API_NAMES_LIST` file.
    :param apis: set of API names.
    :return: `None`
    """
    api_list = list(apis)
    api_list.sort()
    with open(API_NAMES_LIST, "w") as f:
        for api_name in api_list:
            f.write(f"{api_name}\n")


def generate_hashes(hash_func: Callable[..., int], output_file: str, modifier: Callable | None = None, **kwargs: Any) -> None:
    """
    Generate hashes for the specific algorithm.
    :param hash_func: callable function that should take at least `bytes` as a first parameter.
    :param output_file: the path to the file where generated hashes will be written.
    :param modifier: optional callable function to modify API names before hash generation.
    :param kwargs: any additional arguments required by `hash_func` function.
    :return: `None`
    """
    if modifier is None:
        modifier = lambda _: _

    with open(output_file, "w") as f:
        f.write(f"{CSV_HEADER}{LINE_SEPARATOR}")
        for api_name in read_api_names_list():
            api_name_b = bytes(modifier(api_name), "ascii")
            hash_sum = hash_func(api_name_b, **kwargs)
            f.write(f"0x{hash_sum:x},0x{hash_sum:08x},{api_name}{LINE_SEPARATOR}")


def generate_all_hashes() -> None:
    """
    Generates hashes for all algorithms.
    :return: `None`
    """
    for alg_name, hash_func in ALGORITHMS:
        for modifier_name, modifier_func in MODIFIERS:
            generate_hashes(hash_func, f"{alg_name}{modifier_name}.csv", modifier_func)


def update_api_list(dir_path: str) -> None:
    """
    Use this to update api-list.txt with exports from new DLLs.
    :param dir_path: a path to the directory where new DLLs are stored.
    :return: `None`
    """
    def list_dll_exports(dll_path: str) -> set[str]:
        exports = set()
        try:
            pe = pefile.PE(dll_path)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name is not None:
                        # print(f"{exp.name.decode('utf-8')}")
                        exports.add(exp.name.decode("utf-8"))
            else:
                print(f"No export symbols found in {dll_path}")

        except pefile.PEFormatError as e:
            print(f"PEFormatError: {e}, {dll_path}")
        except FileNotFoundError:
            print(f"File not found: {dll_path}")
        except Exception as e:
            print(f"An error occurred: {e}, {dll_path}")
        return exports

    api_list = set(read_api_names_list())
    old_count = len(api_list)
    for fn in listdir(dir_path):
        full_fn = path.join(dir_path, fn)
        dll_exports = list_dll_exports(full_fn)
        api_list.update(dll_exports)
    dump_api_names_list(api_list)
    print(f"Added {len(api_list) - old_count} entries to API list")


if __name__ == "__main__":
    # update_api_list('/clean_dlls')
    generate_all_hashes()
    # An example of ROL24 hash generation:
    # generate_hashes(hash_func=rol_hash, output_file='0xC543A742.csv',
    # modifier=MODIFIER_FUNC_STUB, offset=24, seed=0xC543A742)
