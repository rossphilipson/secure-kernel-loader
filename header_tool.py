#!/usr/bin/env python

#
# Copyright (C) 2018 Advanced Micro Devices, Inc. All rights reserved.
#
# The purpose of this script is to prepend a provided psp signature header to
# a provided binary and update the psp header with the provided firmware
# version and optionally type
# The tool can also be used just to update an existing header
#

import sys
import getopt
import os
import binascii
from array import array

HEADER_VERSION = 0x31534124
HEADER_VERSION_OFFSET_IN_BYTES = 0x10
SIZEFWSIGNED_HEADER_OFFSET_IN_BYTES = 0x14
SECURITY_PATCH_LEVEL_HEADER_OFFSET_IN_BYTES = 0x4C
IMAGEVERSION_HEADER_OFFSET_IN_BYTES = 0x60
HEADER_SIZE_BYTES = 0x100

def main(argv):
    # Process the command line for the parameters for the build
    try:
        opts, args = getopt.getopt(argv, "i:v:s:o:",
                                   ["image=", "version=", "spl=", "output="])
    except getopt.GetoptError:
        print("header_tool.py --image=<firmware image> --version=<firmware version> --spl=<spl version> --output=<output filename>")
        sys.exit(2)

    # Save the arguments
    for opt, arg in opts:
        if opt in ("-i", "--image"):
            image_filename = arg
        elif opt in ("-v", "--version"):
            version = arg
        elif opt in ("-o", "--output"):
            output_filename = arg
        elif opt in ("-s", "--spl"):
            spl = arg

    # Check that all parameters were correctly received
    try:
        image_filename
        version
        spl
        output_filename
    except NameError:
        print("header_tool.py --image=<firmware image> --version=<firmware version> --spl=<security patch level> --output=<output filename>")
        sys.exit(2)

    if os.path.isfile(image_filename) != True:
        print("header_tool.py ERROR: " + image_filename + " does not exist")
        sys.exit(2)

    image = array('I')
    input_file = open(image_filename, "rb")

    image.frombytes(input_file.read())
    AmdSlSize = image[0]
    AmdSlSize = AmdSlSize >> 16

    if (AmdSlSize % 16 != 0):
        AmdSlSize = AmdSlSize +  (16 - (AmdSlSize % 16))
        image[0] = image[0] & 0xFF
        image[0] = image[0] | (AmdSlSize << 16)

    if (os.path.getsize(image_filename) != (64 * 1024)):
        print("Error: AmdSL binary is not size is not equal to 64K ")

    AmdSlSizeInInt = AmdSlSize >> 2

    # Store the ASCI of "$AS1" in header version
    image[AmdSlSizeInInt + int(HEADER_VERSION_OFFSET_IN_BYTES/4)] = HEADER_VERSION
    # Store the AmdSL Size
    image[AmdSlSizeInInt + int(SIZEFWSIGNED_HEADER_OFFSET_IN_BYTES/4)] = AmdSlSize
    image[AmdSlSizeInInt + int(IMAGEVERSION_HEADER_OFFSET_IN_BYTES/4)] = int(version, 16)
    image[AmdSlSizeInInt + int(SECURITY_PATCH_LEVEL_HEADER_OFFSET_IN_BYTES/4)] = int(spl, 16)

    # Since Input and output files may be the same close all files before doing output
    output_file = open(output_filename, "wb")

    # Write the output
    output_file.write(image)
    output_file.close()

    print("header_tool: completed successfully")

if __name__ == "__main__":
    main(sys.argv[1:])
