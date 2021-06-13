@echo off
echo;===== Compilation =====
gcc -Os -fdata-sections -O3 -ffunction-sections -fipa-pta main.c -lm -lzlibstatic -ljansson -o Packer.exe -D_WIN32 -Wl,--gc-sections -Wl,-O1 -Wl,--as-needed -Wl,--strip-all
echo;=== End:Compilation ===
echo;====== Execution ======
rem Packer.exe unpack -i "scb" -o "scb.txt"
rem Packer unpack -i "nsb" -o "test.txt" --prettify --stdout --verbose 1>"data.txt"
rem Packer pack -i "test.txt" -o "nsb_new.gz" --verbose

Packer.exe unpack -i "nsb" -o "nsb.txt" -p --verbose --crlf
rem Packer.exe pack -i "scb.txt" -o "scb.gz" -p --verbose --CRLF
rem Packer.exe pack -i "scb.txt" -o "scb.gz" -p --verbose --stdout

rem Packer.exe unpack -i "scb.gz" -o "scb.txt" -p --verbose --stdout 1>"scb.stdout.txt"

rem Packer.exe pack -i "scb.txt" -o "scb.gz" --verbose --CRLF

rem Packer buildtrb --scb scb --nsb nsb -o trb.txt --verbose --folder Elite\ -p --CRLF

echo;==== End:Execution ====
pause>nul
