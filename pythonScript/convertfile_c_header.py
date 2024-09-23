import os
import sys

def convert_bin_to_c_header(output_file_name, file_paths):
    # Get the base name of the output header file
    header_name = output_file_name

    # Start building the C header content
    header_content = f'#ifndef {header_name.upper()}_H\r\n'
    header_content += f'#define {header_name.upper()}_H\r\n\r\n'
    header_content += f'#include <stdint.h>\r\n\r\n'

    # Process each file
    for file_path in file_paths:
        file_name = os.path.basename(file_path)
        array_name = os.path.splitext(file_name)[0]

        # Read the binary file
        with open(file_path, 'rb') as bin_file:
            binary_data = bin_file.read()

        # Add array size definition
        header_content += f'const size_t {array_name}_size = {len(binary_data)};\n'

        # Start the array declaration
        header_content += f'const uint8_t {array_name}[] = {{\n    '

        # Convert the binary data to a comma-separated list of hex values
        hex_values = [f'0x{byte:02X}' for byte in binary_data]
        
        # Format the hex values into lines of 12 values per line
        line_length = 12
        for i in range(0, len(hex_values), line_length):
            header_content += ', '.join(hex_values[i:i+line_length]) + ',\n    '

        # Close the array definition
        header_content = header_content.rstrip(',\n ') + '\n};\n\n'

    # Add the final guards
    header_content += f'#endif // {header_name.upper()}_H\n'

    # Write the header file
    header_file = f'../{header_name}.h'
    with open(header_file, 'w') as h_file:
        h_file.write(header_content)

    print(f'C header file generated: {header_file}')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python convert_bin_to_c_header.py <binary file 1> <binary file 2> ...")
        sys.exit(1)

    output_file_name = sys.argv[1]

    file_paths = sys.argv[2:]

    print('output file name:'+str(output_file_name))
    print('input paths:'+str(file_paths))

    # Check if all files exist
    for file_path in file_paths:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' does not exist.")
            sys.exit(1)

    print(file_paths)
    convert_bin_to_c_header(output_file_name, file_paths)
