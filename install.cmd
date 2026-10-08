@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Install ssh-cli from cmd.exe. This script does not start PowerShell.
rem Destination: LOCALAPPDATA\ssh-cli\bin  (override with SSH_CLI_BIN)
rem Repository:  jiamingZhao-zhao/ssh-cli    (override with SSH_CLI_REPO=owner/name)
rem Version:     tag from the releases/latest redirect, not api.github.com.
rem              Set SSH_CLI_VERSION (example 0.1.0) to pin a release.
rem              If the redirect cannot be read, the script falls back to 0.1.0.
rem
rem The latest tag is the Location target of
rem https://github.com/<repo>/releases/latest (a /releases/tag/<tag> URL).
rem The zip is https://github.com/<repo>/releases/download/<tag>/ssh-cli_<ver>_windows_<arch>.zip
rem User Path is written with WMI (HKCU\Environment), not setx, so values
rem longer than 1024 characters are kept. An existing directory on the user
rem or machine Path is not appended again.

set "SELF=%~f0"
if not defined SSH_CLI_REPO set "SSH_CLI_REPO=jiamingZhao-zhao/ssh-cli"
set "REPO=%SSH_CLI_REPO%"
if not defined LOCALAPPDATA (
  echo(LOCALAPPDATA is not set 1>&2
  goto :fail
)
if not defined SSH_CLI_BIN set "SSH_CLI_BIN=%LOCALAPPDATA%\ssh-cli\bin"
set "DEST=%SSH_CLI_BIN%"
if not defined DEST (
  echo(SSH_CLI_BIN is empty 1>&2
  goto :fail
)

echo(%REPO%| findstr /R "^[A-Za-z0-9._-][A-Za-z0-9._-]*/[A-Za-z0-9._-][A-Za-z0-9._-]*$" >nul
if errorlevel 1 (
  echo(SSH_CLI_REPO must look like owner/name 1>&2
  goto :fail
)
echo(%REPO%| findstr /C:".." >nul
if not errorlevel 1 (
  echo(SSH_CLI_REPO must look like owner/name 1>&2
  goto :fail
)

call :TrimDest
if not defined DEST (
  echo(SSH_CLI_BIN is empty 1>&2
  goto :fail
)

set "ARCH="
if /I "%PROCESSOR_ARCHITEW6432%"=="AMD64" set "ARCH=amd64"
if /I "%PROCESSOR_ARCHITEW6432%"=="ARM64" set "ARCH=arm64"
if not defined ARCH if /I "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "ARCH=amd64"
if not defined ARCH if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"
if defined ARCH goto :ArchOk
echo(unsupported architecture: %PROCESSOR_ARCHITECTURE% 1>&2
goto :fail
:ArchOk

set "SYS32=%SystemRoot%\System32"
if defined PROCESSOR_ARCHITEW6432 set "SYS32=%SystemRoot%\Sysnative"
set "CURL=%SYS32%\curl.exe"
set "TAR=%SYS32%\tar.exe"
set "CERTUTIL=%SYS32%\certutil.exe"
set "CSCRIPT=%SYS32%\cscript.exe"
call :NeedTool "%CURL%" "curl.exe was not found. Windows 10 or newer is required."
if errorlevel 1 goto :fail
call :NeedTool "%TAR%" "tar.exe was not found. Windows 10 or newer is required."
if errorlevel 1 goto :fail
call :NeedTool "%CERTUTIL%" "certutil.exe was not found."
if errorlevel 1 goto :fail
call :NeedTool "%CSCRIPT%" "cscript.exe was not found."
if errorlevel 1 goto :fail

set "WORKDIR=%TEMP%\ssh-cli-install-%RANDOM%%RANDOM%"
mkdir "%WORKDIR%"
if errorlevel 1 (
  echo(could not create %WORKDIR% 1>&2
  goto :fail
)
mkdir "%WORKDIR%\out"
if errorlevel 1 goto :fail
pushd "%WORKDIR%"
if errorlevel 1 goto :fail
set "PUSHED=1"

if defined SSH_CLI_VERSION (
  call :UsePinned "%SSH_CLI_VERSION%"
  if errorlevel 1 (
    echo(SSH_CLI_VERSION is not a usable version: %SSH_CLI_VERSION% 1>&2
    goto :fail
  )
  goto :HaveVersion
)
call :DiscoverLatest
if not errorlevel 1 goto :HaveVersion
echo(warning: could not resolve the latest release tag; using 0.1.0. Set SSH_CLI_VERSION to pin a release. 1>&2
call :UsePinned "0.1.0"
if errorlevel 1 goto :fail
:HaveVersion

echo(using %TAG% for windows/%ARCH%
set "ASSET=ssh-cli_%VER%_windows_%ARCH%.zip"
set "URL=https://github.com/%REPO%/releases/download/%TAG%/%ASSET%"
set "SUMURL=https://github.com/%REPO%/releases/download/%TAG%/checksums.txt"

"%CURL%" -fsSL --retry 3 --retry-delay 1 -A ssh-cli-install -o "%ASSET%" "%URL%"
if errorlevel 1 (
  echo(failed to download %URL% 1>&2
  echo(Set SSH_CLI_VERSION to a published version, for example 0.1.0. 1>&2
  goto :fail
)
set "ZIPSIZE=0"
for %%S in ("%ASSET%") do set "ZIPSIZE=%%~zS"
if "%ZIPSIZE%"=="0" (
  echo(downloaded file is empty: %URL% 1>&2
  goto :fail
)

"%CURL%" -fsSL --retry 3 --retry-delay 1 -A ssh-cli-install -o "checksums.txt" "%SUMURL%" 2>nul
if errorlevel 1 (
  echo(warning: release has no checksums.txt; the download was not verified 1>&2
  goto :ExtractZip
)
call :VerifySum
if errorlevel 1 goto :fail

:ExtractZip
rem Windows tar.exe is bsdtar. It rejects GNU-only flags such as --force-local.
rem The zip name is relative (no drive-letter colon), so a plain local extract is enough.
"%TAR%" -xf "%ASSET%" -C out
set "TAR_ERR=%ERRORLEVEL%"
if not "%TAR_ERR%"=="0" (
  echo(tar.exe could not extract %ASSET% 1>&2
  goto :fail
)

set "EXE="
for /f "delims=" %%F in ('dir /s /b "out\ssh-cli.exe" 2^>nul') do if not defined EXE set "EXE=%%~fF"
if not defined EXE (
  echo(archive did not contain ssh-cli.exe 1>&2
  goto :fail
)

if not exist "%DEST%\" mkdir "%DEST%"
if errorlevel 1 (
  echo(could not create %DEST% 1>&2
  goto :fail
)
copy /Y "%EXE%" "%DEST%\ssh-cli.exe" >nul
if errorlevel 1 (
  echo(could not copy ssh-cli.exe to %DEST% 1>&2
  goto :fail
)
if not exist "%DEST%\ssh-cli.exe" (
  echo(could not copy ssh-cli.exe to %DEST% 1>&2
  goto :fail
)

call :WritePathScript
if errorlevel 1 goto :fail
"%CSCRIPT%" //nologo //E:JScript "userpath.js" "%DEST%" > "path-result.txt"
if errorlevel 1 (
  echo(failed to update HKCU\Environment Path 1>&2
  goto :fail
)
set "PATH_LINE="
set /p PATH_LINE=<"path-result.txt"
if not defined PATH_LINE (
  echo(failed to update HKCU\Environment Path 1>&2
  goto :fail
)
set "USER_STATE="
set "SESSION_STATE="
for /f "tokens=1,2" %%A in ("%PATH_LINE%") do set "USER_STATE=%%A" & set "SESSION_STATE=%%B"
if "%USER_STATE%"=="user-yes" goto :PathReady
if "%USER_STATE%"=="user-no" goto :PathReady
echo(failed to update HKCU\Environment Path 1>&2
goto :fail
:PathReady

set "NEWPATH=%PATH%"
set "DO_SET=0"
if not "%SESSION_STATE%"=="session-add" goto :SessionReady
set "DO_SET=1"
if not defined NEWPATH goto :SessionEmpty
if "%NEWPATH:~-1%"==";" goto :SessionJoinSemi
set "NEWPATH=%NEWPATH%;%DEST%"
goto :SessionReady
:SessionJoinSemi
set "NEWPATH=%NEWPATH%%DEST%"
goto :SessionReady
:SessionEmpty
set "NEWPATH=%DEST%"
:SessionReady

echo(installed %DEST%\ssh-cli.exe %VER%
if "%USER_STATE%"=="user-yes" echo(Added %DEST% to user PATH. This session can run: ssh-cli version
if "%USER_STATE%"=="user-yes" echo(Sign out and back in so Start menu windows inherit the user PATH.
if "%USER_STATE%"=="user-no" if "%SESSION_STATE%"=="session-add" echo(Added %DEST% to the current session PATH. New terminals already include it.
if "%PUSHED%"=="1" popd
set "PUSHED="
if defined WORKDIR if exist "%WORKDIR%\" rmdir /s /q "%WORKDIR%"
endlocal & if "%DO_SET%"=="1" set "PATH=%NEWPATH%"
exit /b 0

:fail
if "%PUSHED%"=="1" popd
set "PUSHED="
if defined WORKDIR if exist "%WORKDIR%\" rmdir /s /q "%WORKDIR%"
endlocal & exit /b 1

:NeedTool
if exist "%~1" exit /b 0
echo(%~2 1>&2
exit /b 1

:TrimDest
if not defined DEST exit /b 0
if not "%DEST:~-1%"=="\" exit /b 0
if "%DEST:~3%"=="" exit /b 0
set "DEST=%DEST:~0,-1%"
goto :TrimDest

:UsePinned
set "RAW=%~1"
if not defined RAW exit /b 1
if "%RAW%"=="" exit /b 1
call :CheckToken "%RAW%"
if errorlevel 1 exit /b 1
if /I "%RAW:~0,1%"=="v" goto :PinnedV
set "VER=%RAW%"
set "TAG=v%RAW%"
goto :PinnedCheck
:PinnedV
set "VER=%RAW:~1%"
if not defined VER exit /b 1
if "%VER%"=="" exit /b 1
set "TAG=v%VER%"
:PinnedCheck
call :CheckToken "%TAG%"
if errorlevel 1 exit /b 1
call :CheckToken "%VER%"
if errorlevel 1 exit /b 1
exit /b 0

:DiscoverLatest
"%CURL%" -fsSL --retry 3 --retry-delay 1 -A ssh-cli-install -D "headers.txt" -o "latest.html" "https://github.com/%REPO%/releases/latest" 2>nul
if errorlevel 1 exit /b 1
findstr /I /B /C:"location:" "headers.txt" > "locations.txt"
findstr /I /C:"/releases/tag/" "locations.txt" > "tagloc.txt"
set "EFFECTIVE="
for /f "usebackq tokens=1* delims= " %%A in ("tagloc.txt") do set "EFFECTIVE=%%B"
if not defined EFFECTIVE exit /b 1
set "TAG=%EFFECTIVE%"
call :LastSegment
if errorlevel 1 exit /b 1
if not defined TAG exit /b 1
set "VER=%TAG%"
if /I "%VER:~0,1%"=="v" set "VER=%VER:~1%"
if not defined VER exit /b 1
if "%VER%"=="" exit /b 1
call :CheckToken "%TAG%"
if errorlevel 1 exit /b 1
call :CheckToken "%VER%"
if errorlevel 1 exit /b 1
exit /b 0

:LastSegment
if not defined TAG exit /b 1
:LastTrim
if not defined TAG exit /b 1
if "%TAG%"=="" exit /b 1
if "%TAG:~0,1%"=="/" goto :LastLead
if "%TAG:~-1%"=="/" goto :LastTrail
echo(%TAG%| findstr /C:"/" >nul
if errorlevel 1 exit /b 0
for /f "tokens=1* delims=/" %%A in ("%TAG%") do set "TAG=%%B"
goto :LastTrim
:LastLead
set "TAG=%TAG:~1%"
goto :LastTrim
:LastTrail
set "TAG=%TAG:~0,-1%"
goto :LastTrim

:CheckToken
set "TOKEN=%~1"
if not defined TOKEN exit /b 1
if "%TOKEN%"=="" exit /b 1
rem Prefix with A so the line cannot be skipped by eol=; and every allowed
rem character is a delimiter. A leftover token means the version is not safe.
for /f "delims=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-" %%X in ("A%TOKEN%") do exit /b 1
exit /b 0

:VerifySum
set "WANT="
for /f "usebackq tokens=1*" %%A in ("checksums.txt") do call :ConsiderSum "%%A" "%%B"
if not defined WANT (
  echo(checksums.txt has no entry for %ASSET% 1>&2
  exit /b 1
)
"%CERTUTIL%" -hashfile "%ASSET%" SHA256 > "hash.txt"
if errorlevel 1 (
  echo(certutil could not hash %ASSET% 1>&2
  exit /b 1
)
set "GOT="
for /f "usebackq delims=" %%H in ("hash.txt") do call :ConsiderHash "%%H"
if not defined GOT (
  echo(certutil did not return a SHA256 for %ASSET% 1>&2
  exit /b 1
)
if /I not "%WANT%"=="%GOT%" (
  echo(checksum mismatch for %ASSET% 1>&2
  exit /b 1
)
exit /b 0

:ConsiderSum
set "HEX=%~1"
set "NAME=%~2"
if not defined HEX exit /b 0
if "%HEX:~0,1%"=="#" exit /b 0
if not "%HEX:~64,1%"=="" exit /b 0
if "%HEX:~63,1%"=="" exit /b 0
echo(%HEX%| findstr /R "^[0-9A-Fa-f][0-9A-Fa-f]*$" >nul
if errorlevel 1 exit /b 0
if not defined NAME exit /b 0
if "%NAME:~0,1%"=="*" set "NAME=%NAME:~1%"
if /I "%NAME%"=="%ASSET%" set "WANT=%HEX%"
exit /b 0

:ConsiderHash
if defined GOT exit /b 0
set "LINE=%~1"
if not defined LINE exit /b 0
set "LINE=%LINE: =%"
if not defined LINE exit /b 0
if not "%LINE:~64,1%"=="" exit /b 0
if "%LINE:~63,1%"=="" exit /b 0
echo(%LINE%| findstr /R "^[0-9A-Fa-f][0-9A-Fa-f]*$" >nul
if errorlevel 1 exit /b 0
set "GOT=%LINE%"
exit /b 0

:WritePathScript
set "JS=userpath.js"
if exist "%JS%" del /f /q "%JS%"
rem Copy next to a parenthesis-free name so the FOR /F command string stays valid.
copy /Y "%SELF%" "source.cmd" >nul
if errorlevel 1 exit /b 1
for /f "tokens=1,2* delims=@" %%A in ('findstr /B /C:"rem @JS@" "source.cmd"') do >>"%JS%" echo(%%C
if not exist "%JS%" exit /b 1
exit /b 0

rem The lines below are JScript extracted by :WritePathScript. cmd treats them as comments.
rem @JS@var dest = "";
rem @JS@if (WScript.Arguments.length) dest = String(WScript.Arguments(0));
rem @JS@if (dest.length == 0) fail("missing destination");
rem @JS@var HKCU = 0x80000001;
rem @JS@var HKLM = 0x80000002;
rem @JS@var userKey = "Environment";
rem @JS@var machineKey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
rem @JS@var shell = new ActiveXObject("WScript.Shell");
rem @JS@var locator = new ActiveXObject("WbemScripting.SWbemLocator");
rem @JS@locator.Security_.ImpersonationLevel = 3;
rem @JS@var svc = locator.ConnectServer(".", "root\\default");
rem @JS@svc.Security_.ImpersonationLevel = 3;
rem @JS@var reg = svc.Get("StdRegProv");
rem @JS@function positive(n) {
rem @JS@  var s = String(n);
rem @JS@  if (s == "0") return false;
rem @JS@  if (s.charAt(0) == "-") return false;
rem @JS@  return true;
rem @JS@}
rem @JS@function fail(msg) {
rem @JS@  WScript.StdErr.WriteLine(msg);
rem @JS@  WScript.Quit(1);
rem @JS@}
rem @JS@function callReg(hive, subkey, method, value, hasValue) {
rem @JS@  var inp = reg.Methods_.Item(method).InParameters.SpawnInstance_();
rem @JS@  inp.hDefKey = hive;
rem @JS@  inp.sSubKeyName = subkey;
rem @JS@  inp.sValueName = "Path";
rem @JS@  if (hasValue) inp.sValue = value;
rem @JS@  return reg.ExecMethod_(method, inp);
rem @JS@}
rem @JS@function trimEnds(p) {
rem @JS@  var start = 0;
rem @JS@  var end = p.length;
rem @JS@  while (start - end) {
rem @JS@    var ch = p.charAt(start);
rem @JS@    if (ch == " ") start = start + 1;
rem @JS@    else if (ch == "\t") start = start + 1;
rem @JS@    else break;
rem @JS@  }
rem @JS@  while (positive(end - start)) {
rem @JS@    var ch2 = p.charAt(end - 1);
rem @JS@    if (ch2 == " ") end = end - 1;
rem @JS@    else if (ch2 == "\t") end = end - 1;
rem @JS@    else break;
rem @JS@  }
rem @JS@  return p.substring(start, end);
rem @JS@}
rem @JS@function norm(p) {
rem @JS@  var s = String(p);
rem @JS@  try {
rem @JS@    s = shell.ExpandEnvironmentStrings(s);
rem @JS@  } catch (err) {
rem @JS@    s = String(p);
rem @JS@  }
rem @JS@  s = trimEnds(s);
rem @JS@  while (positive(s.length - 3)) {
rem @JS@    var ch = s.charAt(s.length - 1);
rem @JS@    if (ch == "\\") s = s.substring(0, s.length - 1);
rem @JS@    else if (ch == "/") s = s.substring(0, s.length - 1);
rem @JS@    else break;
rem @JS@  }
rem @JS@  return s.toLowerCase();
rem @JS@}
rem @JS@function readValue(hive, subkey) {
rem @JS@  var expanded = callReg(hive, subkey, "GetExpandedStringValue", "", false);
rem @JS@  if (expanded.ReturnValue == 0) {
rem @JS@    var expandedValue = "";
rem @JS@    if (expanded.sValue) expandedValue = String(expanded.sValue);
rem @JS@    return { ok: true, missing: false, write: "SetExpandedStringValue", value: expandedValue };
rem @JS@  }
rem @JS@  var plain = callReg(hive, subkey, "GetStringValue", "", false);
rem @JS@  if (plain.ReturnValue == 0) {
rem @JS@    var plainValue = "";
rem @JS@    if (plain.sValue) plainValue = String(plain.sValue);
rem @JS@    return { ok: true, missing: false, write: "SetStringValue", value: plainValue };
rem @JS@  }
rem @JS@  var missing = false;
rem @JS@  if (expanded.ReturnValue == 2) {
rem @JS@    if (plain.ReturnValue == 2) missing = true;
rem @JS@  }
rem @JS@  if (missing) return { ok: true, missing: true, write: "SetExpandedStringValue", value: "" };
rem @JS@  return { ok: false, missing: false, write: "", value: "" };
rem @JS@}
rem @JS@function listHas(list, wanted) {
rem @JS@  var items = String(list).split(";");
rem @JS@  var n = 0;
rem @JS@  var hit = false;
rem @JS@  while (n - items.length) {
rem @JS@    if (items[n].length) {
rem @JS@      if (norm(items[n]) == wanted) hit = true;
rem @JS@    }
rem @JS@    n = n + 1;
rem @JS@  }
rem @JS@  return hit;
rem @JS@}
rem @JS@function appendDir(current, dir) {
rem @JS@  var next = String(current);
rem @JS@  while (next.length) {
rem @JS@    if (next.charAt(next.length - 1) == ";") next = next.substring(0, next.length - 1);
rem @JS@    else break;
rem @JS@  }
rem @JS@  if (next.length == 0) return dir;
rem @JS@  return next + ";" + dir;
rem @JS@}
rem @JS@var want = norm(dest);
rem @JS@if (want.length == 0) fail("missing destination");
rem @JS@var user = readValue(HKCU, userKey);
rem @JS@if (user.ok == false) fail("could not read HKCU\\Environment\\Path");
rem @JS@var machine = readValue(HKLM, machineKey);
rem @JS@var onMachine = false;
rem @JS@if (machine.ok) onMachine = listHas(machine.value, want);
rem @JS@var onUser = false;
rem @JS@if (user.missing == false) onUser = listHas(user.value, want);
rem @JS@var session = shell.Environment("PROCESS").Item("Path");
rem @JS@if (session == null) session = "";
rem @JS@var onSession = listHas(session, want);
rem @JS@var userWord = "user-no";
rem @JS@if (onUser == false) {
rem @JS@  if (onMachine == false) {
rem @JS@    var next = appendDir(user.value, dest);
rem @JS@    var written = callReg(HKCU, userKey, user.write, next, true);
rem @JS@    if (written.ReturnValue == 0) userWord = "user-yes";
rem @JS@    else fail("could not write HKCU\\Environment\\Path");
rem @JS@  }
rem @JS@}
rem @JS@var sessionWord = "session-keep";
rem @JS@if (onSession == false) sessionWord = "session-add";
rem @JS@WScript.Echo(userWord + " " + sessionWord);
