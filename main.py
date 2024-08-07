from algorithms import *
import zlib

API_NAMES_LIST = 'api-list.txt'
CSV_HEADER = 'HASH,HASH_W_LEADING_ZEROS,API_NAME'
LINE_SEPARATOR = '\n'

MODIFIER_FUNC_STUB = lambda _: _
MODIFIERS = (
    ('', MODIFIER_FUNC_STUB),
    ('_lowercase', lambda x: x.lower()),
    ('_uppercase', lambda x: x.upper()),
)
ALGORITHMS = (
    ('bzip_crc32', zlib.crc32),
    ('bzip2_crc32', bzip2_crc32)
)


def read_api_names_list():
    with open(API_NAMES_LIST, 'r') as f:
        api_names = f.read().splitlines(keepends=False)
    return api_names


def generate_hashes(hash_func, output_file, modifier=None, **kwargs):
    if modifier is None:
        modifier = lambda _: _

    with open(output_file, 'w') as f:
        f.write(f'{CSV_HEADER}{LINE_SEPARATOR}')
        for api_name in read_api_names_list():
            hash_sum = hash_func(bytes(modifier(api_name), 'ascii'), **kwargs)
            f.write(f'0x{hash_sum:x},0x{hash_sum:08x},{api_name}{LINE_SEPARATOR}')


def generate_all_hashes():
    for alg_name, hash_func in ALGORITHMS:
        for modifier_name, modifier_func in MODIFIERS:
            generate_hashes(hash_func, f'{alg_name}{modifier_name}.csv', modifier_func)


if __name__ == '__main__':
    generate_all_hashes()
    # An example of ROL24 hash generation:
    # generate_hashes(hash_func=ro  l_hash, output_file='0xC543A742.csv', modifier=MODIFIER_FUNC_STUB, offset=24, seed=0xC543A742)
