#!/usr/bin/env python3

"""
Usage:
- Extract the symbol information using https://github.com/mandiant/GoReSym
- Store the output in a file called `goresym_out.txt` 
- Within radare, execute this script:
[0x........]> . rename.py
- Wait
- Appreciate the symbols within radare2!
"""

import json, r2pipe, re, sys

r2p = r2pipe.open()

# load the data from the json dump produced by goresym
with open("goresym_out.txt", "r") as data:
    content = json.load(data)

    # extract the information we need in order to assemble the radare2 command
    # used to name the functions
    userFunctions = content["UserFunctions"]
    for function in userFunctions:
        start = function["Start"]
        end  = function["End"]
        packageName = function["PackageName"]
        fullName = function["FullName"]

        fullName = fullName.replace("(", "_").replace(")", "_").replace("*", "_").replace(".", "_").replace("/", "_")
        fullName = re.sub("[_]+", "_", fullName)
        fullName = re.sub("(\[.+\])", "", fullName)

        if hex(start) != -1:
            # delete the existing function defined at that address, should one
            # have already be defined
            command = f"af- {hex(start)}"
            r2p.cmd(command)

            # define the new function with the given name and size
            command = f"af+ {hex(start)} sym.{fullName} {end-start}"
            r2p.cmd(command)

            # define a new basic block at address of the function
            command = f"afb+ {hex(start)} sym.{fullName} {end-start}"
            r2p.cmd(command)
