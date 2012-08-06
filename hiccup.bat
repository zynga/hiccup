@echo off

set COUNT=0

set STARTDIR=%CD%\
set BATDIR=%~dp0
cd /D %BATDIR%

for /f "tokens=*" %%a in ( 
'forfiles /P %BATDIR% /M burpsuite_*.jar /C "cmd /c echo @fname" ^| find /C "burpsuite"' 
) do ( 
set COUNT=%%a
)


if %COUNT%==1 goto ONE
if %COUNT% gtr 1 goto MANY
goto NONE

:ONE
for %%X in (burpsuite_*.jar) do set BURP_PACKAGE=%%X
goto EXECBURP

:MANY
for %%X in (burpsuite_*.jar) do (
	choice /C:ny /M "Found %COUNT% Burp packages; use %%X"
	if ERRORLEVEL 2 ( 
		set BURP_PACKAGE=%%X
		goto EXECBURP
	)
)
goto NONE


:NONE
echo ERROR: A necessary Burp Suite package could not be located, or was not selected; download from http://portswigger.net/burp/download.html, or view README file for more instructions.
cd /D %STARTDIR%
pause
goto EOF

:EXECBURP
echo Initializing Burp with package %BURP_PACKAGE%...
java -Xmx1024m -classpath %BURP_PACKAGE%;lib\BurpExtender.jar;lib\sqlitejdbc-v056.jar -Dpython.path=%CD%;%CD%\lib;%CD%\hiccup;%CD%\plugins burp.StartBurp
goto EOF


:EOF
cd %STARTDIR%
exit /B
