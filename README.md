# Description
A starter script for x86\_64 linux PWNing. Designed to be used for stripped ELF binaries.

# Usage
<p>This script is intended to be used after doing some reverse engineering. Whatever tool you've used, you'll need a table of the symbols in the binary in a CSV file. In ghdira, you can do this With the following method:</p>

<p>First, click the button to open the symbol table. (Or use ctrl+T).</p>
<p algin="center">
<img src = https://github.com/Lukerd-29-00/pwn_starter/blob/main/symbol_table.png?raw=true width=800 height=500 />
</p>
<p>Next, Highlight the rows with the functions and variables you want. You can highlight several by holding ctrl and clicking them individually, or highlight everything between two rows with the shift key Then right-click and select Export > Export to CSV.</p>
<p align = "center">
<img src=https://github.com/Lukerd-29-00/pwn_starter/blob/main/export.png?raw=true width=800 height=500 />
</p>
Save the resulting file in the folder with your exploit, and write the name/path in the symbolsFile global variable. Now, when you launch with pwntools's magic GDB argument, the program will automatically assign the addresses of the functions you've exported to variables. You can set a breakpoint with the command
`b *$<function>`.
