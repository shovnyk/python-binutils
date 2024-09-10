# Output similar to hexdump produced by tools like `xxd` or `hd`.
offset = 0
def process_hexdump(chunk, chunksize):
    global offset

    # Print hex representation of the chunk.
    hexdump = ''.join(f'{byte:02X}' for byte in chunk)
    print(f'{offset:08X}: {hexdump}')

    # Update offset.
    offset += chunksize


# Output can be embedded into a header C source file.
def process_cbuffer(chunk, dummy, **kwargs):
    try:
        perline = kwargs['perline']
    except KeyError:
        perline = 16

    # Loop through the chunk in increments of chunksize
    for i in range(0, len(chunk), perline):
        # Extract a slice of the chunk with size chunksize
        chunk_slice = chunk[i:i+perline]
        # Convert each byte to hexadecimal and join with ", " in the required format
        formatted_chunk = ", ".join(f"0x{byte:02X}" for byte in chunk_slice)
        print(f"\t{formatted_chunk},")

# Map output format to their respective handler functions.
process_table = {
    'hexdump': process_hexdump,
    'cbuffer': process_cbuffer
}

# Read in the binary contents of a file, process them and dump to console in some format.
def dumpfile(filepath, chunksize=256, output='hexdump'):

    # Determine processing based on output format specified.
    output_formats = process_table.keys()
    if output not in output_formats:
        raise ValueError(f'Invalid output format "{output}" specified. Must be one of: {list(output_formats)}')
    else:
        process_func = process_table[output]

    if output == 'cbuffer':
        print('static const uint8_t buffer[] = {')

    # Try opening the file and applying processing function.
    try:
        with open(filepath, 'rb') as file:
            while True:

                # Read the file in chunks to handle larger files.
                # Tradeoff: large chunk size -> less IO operations: faster but more memory.
                chunk = file.read(chunksize)

                # Process the chunk.
                process_func(chunk, chunksize)

                # Last chunk read will always be smaller than the chunk size
                # (or zero). This will save one last read in the former case.
                if len(chunk) < chunksize:
                    if output == 'cbuffer':
                        print('};')
                    break

    # Handle possible exceptions when opening the file fails.
    except FileNotFoundError:
        print(f"'{filepath}' does not exist.")
    except IOError as e:
        print(f"Error opening file: {e}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <filepath> [output-format]")
        sys.exit(1)
    else:
        filepath = sys.argv[1]
        format = 'hexdump'
        if len(sys.argv) >= 3:
            format = sys.argv[2]
        try:
            dumpfile(filepath, output=format)
            sys.exit(0)
        except Exception as e:
            print(e)
            sys.exit(2)


"""
Output:
-------
$ python3 ./dumpfile.py textfile
00000000: 7468 6973 2069 7320 6120 6C69 6E65 206F 6620 7465 7874 2E0A 0A

Compare with hexdump tool:
--------------------------
$ xxd textfile
00000000: 7468 6973 2069 7320 6120 6c69 6e65 206f  this is a line o
00000010: 6620 7465 7874 2e0a 0a                   f text...
"""
