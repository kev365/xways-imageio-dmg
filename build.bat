@echo off
REM ============================================================================
REM  Build xways-imageio-dmg -> ImageIO_DMG.dll (x64) with MSVC cl.exe.
REM
REM  IMPORTANT: this is an *Image I/O API* plugin, NOT a regular X-Tension.
REM    - The DLL filename MUST match the mask `Image*.dll` (X-Ways scans for
REM      that exact prefix), so it deliberately does not follow the
REM      xways-<name>.dll convention of the X-Tensions.
REM    - Deploy path for the 64-bit DLL: <X-Ways install>\x64\  (the install
REM      root is silently ignored for 64-bit Image*.dll plugins). NOT under
REM      xtensions\ - that folder is for the other API class.
REM    - X-Ways loads at most two Image*.dll plugins. The Evimetry AFF4 reader
REM      (ImageIOAFF4.dll) usually occupies one slot already.
REM
REM  Output is staged to xways-install-root\x64\ImageIO_DMG.dll - merge the
REM  contents of xways-install-root\ onto the X-Ways install folder.
REM
REM  Optional mirror: set IMAGEIO_DMG_DEPLOY=<X-Ways install root> (env var) or
REM  create a one-line .deploy.local file with that path, and the DLL is also
REM  copied into <root>\x64\ (warns, does not fail, if X-Ways has it locked).
REM
REM  Auto-bootstraps the VS x64 toolchain if cl.exe isn't on PATH yet.
REM ============================================================================

setlocal EnableDelayedExpansion

REM --- Bootstrap VS x64 toolchain if needed ----------------------------------
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
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) do if not defined VCVARS if exist %%V set "VCVARS=%%~V"
if not defined VCVARS (
    echo ERROR: Could not find vcvars64.bat. Install the MSVC C++ build tools, or
    echo run this script from a "x64 Native Tools Command Prompt for VS 2019/2022".
    exit /b 1
)
echo Bootstrapping MSVC x64 environment from:
echo     !VCVARS!
call "!VCVARS!" >nul 2>nul
if errorlevel 1 (
    echo ERROR: vcvars64.bat reported failure.
    exit /b 1
)

:have_toolchain

set SRC=xways-imageio-dmg
set OUT=ImageIO_DMG.dll
set INCS=/I. /Ivendor\miniz /Ivendor\xz-embedded /Ivendor\bzip2 /Ivendor\lzfse
set VENDORDEFS=/DXZ_USE_CRC64 /DBZ_NO_STDIO /DMINIZ_NO_STDIO /DMINIZ_NO_ARCHIVE_APIS /DMINIZ_NO_TIME /DMINIZ_NO_MALLOC_OVERRIDE
set CXXFLAGS=/nologo /std:c++17 /W3 /EHsc /O2 /MT /utf-8 /DUNICODE /D_UNICODE %VENDORDEFS% %INCS%
REM /wd4244 /wd4267 /wd4996: benign narrowing + CRT-deprecation noise in the
REM vendored decoders (upstream code we don't patch). Our own C++ keeps full /W3.
set CFLAGS=/nologo /W3 /wd4244 /wd4267 /wd4996 /wd4267 /O2 /MT /utf-8 %VENDORDEFS% %INCS%
set LDFLAGS=/DLL /DEF:%SRC%.def /OUT:%OUT% /MACHINE:X64
set LIBS=bcrypt.lib Crypt32.lib User32.lib Gdi32.lib

if exist *.obj del /q *.obj
if exist *.res del /q *.res

REM --- Resources (password dialog + VERSIONINFO) -----------------------------
rc /nologo /fo %SRC%.res %SRC%.rc || goto :fail

REM --- Vendored decoders (compiled as C) ---------------------------------------
cl %CFLAGS% /c vendor\miniz\miniz.c                    || goto :fail
cl %CFLAGS% /c vendor\xz-embedded\xz_dec_stream.c      || goto :fail
cl %CFLAGS% /c vendor\xz-embedded\xz_dec_lzma2.c       || goto :fail
cl %CFLAGS% /c vendor\xz-embedded\xz_crc32.c           || goto :fail
cl %CFLAGS% /c vendor\xz-embedded\xz_crc64.c           || goto :fail
cl %CFLAGS% /c vendor\bzip2\blocksort.c                || goto :fail
cl %CFLAGS% /c vendor\bzip2\huffman.c                  || goto :fail
cl %CFLAGS% /c vendor\bzip2\crctable.c                 || goto :fail
cl %CFLAGS% /c vendor\bzip2\randtable.c                || goto :fail
cl %CFLAGS% /c vendor\bzip2\compress.c                 || goto :fail
cl %CFLAGS% /c vendor\bzip2\decompress.c               || goto :fail
cl %CFLAGS% /c vendor\bzip2\bzlib.c                    || goto :fail
cl %CFLAGS% /c vendor\lzfse\lzfse_fse.c                || goto :fail
cl %CFLAGS% /c vendor\lzfse\lzfse_decode.c             || goto :fail
cl %CFLAGS% /c vendor\lzfse\lzfse_decode_base.c        || goto :fail
cl %CFLAGS% /c vendor\lzfse\lzvn_decode_base.c         || goto :fail

REM --- Plugin sources (C++) ----------------------------------------------------
cl %CXXFLAGS% /c dmg_koly.cpp       || goto :fail
cl %CXXFLAGS% /c dmg_mish.cpp       || goto :fail
cl %CXXFLAGS% /c dmg_plist.cpp      || goto :fail
cl %CXXFLAGS% /c dmg_rsrc.cpp       || goto :fail
cl %CXXFLAGS% /c dmg_blockmap.cpp   || goto :fail
cl %CXXFLAGS% /c dmg_decoder.cpp    || goto :fail
cl %CXXFLAGS% /c udif_source.cpp    || goto :fail
cl %CXXFLAGS% /c dmg_verify.cpp     || goto :fail
cl %CXXFLAGS% /c encrypted_source.cpp || goto :fail
cl %CXXFLAGS% /c password_dialog.cpp  || goto :fail
cl %CXXFLAGS% /c dmg_open.cpp         || goto :fail
cl %CXXFLAGS% /c sparse_source.cpp    || goto :fail
cl %CXXFLAGS% /c %SRC%.cpp          || goto :fail

link %LDFLAGS% *.obj %SRC%.res %LIBS% || goto :fail

echo.
echo Built: %OUT%

REM --- Export check: exactly the three undecorated IIO_* names ----------------
dumpbin /nologo /exports %OUT% | findstr /C:"IIO_Init" >nul || (echo ERROR: IIO_Init not exported & goto :fail)
dumpbin /nologo /exports %OUT% | findstr /C:"IIO_Work" >nul || (echo ERROR: IIO_Work not exported & goto :fail)
dumpbin /nologo /exports %OUT% | findstr /C:"IIO_Done" >nul || (echo ERROR: IIO_Done not exported & goto :fail)
echo Exports OK: IIO_Init IIO_Work IIO_Done

REM --- Stage: xways-install-root\x64\ImageIO_DMG.dll --------------------------
if not exist xways-install-root\x64 mkdir xways-install-root\x64
copy /Y "%OUT%" "xways-install-root\x64\%OUT%" >nul || goto :fail
echo Staged: xways-install-root\x64\%OUT%

REM --- Optional mirror into a local X-Ways install ----------------------------
set "DEPLOY=%IMAGEIO_DMG_DEPLOY%"
if not defined DEPLOY if exist .deploy.local set /p DEPLOY=<.deploy.local
if defined DEPLOY (
    if exist "!DEPLOY!\x64\" (
        copy /Y "%OUT%" "!DEPLOY!\x64\%OUT%" >nul 2>nul
        if errorlevel 1 (
            echo WARNING: could not copy to "!DEPLOY!\x64\" ^(X-Ways open / DLL locked?^)
        ) else (
            echo Mirrored: !DEPLOY!\x64\%OUT%
        )
    ) else (
        echo WARNING: deploy root "!DEPLOY!" has no x64\ subfolder; not mirrored
    )
)

REM Remove the project-root DLL + intermediates; the loadable copy is the staged one.
if exist "%OUT%" del /Q "%OUT%" 2>nul
if exist "ImageIO_DMG.exp" del /Q "ImageIO_DMG.exp" 2>nul
if exist "ImageIO_DMG.lib" del /Q "ImageIO_DMG.lib" 2>nul
if exist *.obj del /q *.obj
if exist *.res del /q *.res

echo.
echo Next step: copy xways-install-root\x64\%OUT% into your X-Ways install's x64\
echo folder (next to xwforensics64.exe's x64\ siblings such as ImageIOAFF4.dll).
exit /b 0

:fail
echo.
echo BUILD FAILED
exit /b 1
