from io import TextIOWrapper
import re
import typing
from pwn import *
import os.path as path

context.arch = "amd64"
libc = ELF("./libc.so.6")
filename = "./chal"
ip = "0.0.0.0"
port = 0
symbolsFile = "symbols.csv" #Export the symbol table from ghidra as a CSV and save it in this file.
gdbscript = ".gdbscript"

def lines(file: TextIOWrapper, skipFirst: bool = False)->str:
    x = file.readline()
    if skipFirst:
        x = file.readline()
    while x:
        yield x
        x = file.readline()

def parseSymbols(filename: str, pie_base: int, page_size: int = 4096)->typing.Tuple[str,int]:
    if not re.match(r".*.csv",filename):
        raise ValueError(f"Cannot parse non csv file {filename}!")
    if not pie_base % page_size == 0:
        raise ValueError("PIE must be page aligned!")
    registers = re.compile(r"^(?:[bacd][lh]|[re][sbi]p|[csdefg]s|r(?:[89]|1[0-5])|[re]{0,1}(?:[abcd]x|[sd]i))$")
    csvPattern = re.compile(r'^"((?:[^,"]|\\.)+)","((?:[^,"]|\\.)+)",')
    print(filename)
    with open(filename,"r") as f:
        for line in lines(f,True):
            match: re.Match = re.search(csvPattern,line)
            if re.match(registers,match.group(1)):
              raise ValueError(f"Cannot handle symbol {match.group(1)} @ {match.group(2)} with the name of a register!")
            yield match.group(1), pie_base + int(match.group(2)[-4:],16)

def get_PIE(r: process)->int:
    with open("/proc/%d/maps" % (r.pid)) as f:
        maps = f.readlines()
        base = maps[0].split("-")[0]
    return int(base, 16)

def get_gdbscript(symbolsFile: str,p: process)->None:
  with open(gdbscript,"w") as f:
    for func,addr in parseSymbols(symbolsFile,get_PIE(p)):
      f.write(f"set ${func}={addr}\n")

if args.REMOTE:
  p = remote(ip,port)
  log.success("Connection established.")
elif args.GDB:
  p = process(filename)
  log.success(f"Process {p.pid} initialized")
  if not path.exists(gdbscript):
    log.info("writing gdbscript")
    get_gdbscript(symbolsFile,p)
    log.success("Wrote gdbscript!")
  with open(gdbscript,"r") as f:
    gdb.attach(p,gdbscript=f)
  log.success("GDB attached successfully.")
else:
  p = process(filename)
  log.success(f"Process {p.pid} initialized")



p.interactive()
