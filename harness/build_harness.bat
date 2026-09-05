@echo off
REM Build harness\dmgtest.exe from the same sources as ImageIO_DMG.dll.
REM Run from the project folder (plugins\xways-imageio-dmg) or from harness\.

setlocal EnableDelayedExpansion
if exist ..\xways-imageio-dmg.def cd ..

where cl >nul 2>nul && goto :have_toolchain
set "VCVARS="
for %%V in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
) do if not defined VCVARS if exist %%V set "VCVARS=%%~V"
if not defined VCVARS ( echo ERROR: vcvars64.bat not found & exit /b 1 )
call "!VCVARS!" >nul 2>nul
:have_toolchain

set INCS=/I. /Ivendor\miniz /Ivendor\xz-embedded /Ivendor\bzip2 /Ivendor\lzfse
set VENDORDEFS=/DXZ_USE_CRC64 /DBZ_NO_STDIO /DMINIZ_NO_STDIO /DMINIZ_NO_ARCHIVE_APIS /DMINIZ_NO_TIME /DMINIZ_NO_MALLOC_OVERRIDE
set CXXFLAGS=/nologo /std:c++17 /W3 /EHsc /O2 /MT /utf-8 /DUNICODE /D_UNICODE %VENDORDEFS% %INCS% /Foharness\
set CFLAGS=/nologo /W3 /wd4244 /wd4267 /wd4996 /O2 /MT /utf-8 %VENDORDEFS% %INCS% /Foharness\

if exist harness\*.obj del /q harness\*.obj

for %%F in (vendor\miniz\miniz.c vendor\xz-embedded\xz_dec_stream.c vendor\xz-embedded\xz_dec_lzma2.c vendor\xz-embedded\xz_crc32.c vendor\xz-embedded\xz_crc64.c vendor\bzip2\blocksort.c vendor\bzip2\huffman.c vendor\bzip2\crctable.c vendor\bzip2\randtable.c vendor\bzip2\compress.c vendor\bzip2\decompress.c vendor\bzip2\bzlib.c vendor\lzfse\lzfse_fse.c vendor\lzfse\lzfse_decode.c vendor\lzfse\lzfse_decode_base.c vendor\lzfse\lzvn_decode_base.c) do (
    cl %CFLAGS% /c %%F || goto :fail
)
for %%F in (dmg_koly.cpp dmg_mish.cpp dmg_plist.cpp dmg_rsrc.cpp dmg_blockmap.cpp dmg_decoder.cpp udif_source.cpp dmg_verify.cpp encrypted_source.cpp dmg_open.cpp sparse_source.cpp harness\dmgtest.cpp) do (
    cl %CXXFLAGS% /c %%F || goto :fail
)
link /nologo /OUT:harness\dmgtest.exe /MACHINE:X64 harness\*.obj bcrypt.lib || goto :fail
del /q harness\*.obj
echo Built: harness\dmgtest.exe
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
