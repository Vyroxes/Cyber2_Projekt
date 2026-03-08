@echo off
chcp 65001

set NAME=Szyfrowanie i deszyfrowanie plików
set FOLDER=dist\%NAME%
set ICON=icon.ico
set MAIN_SCRIPT=main.py

pyinstaller --windowed --icon="%ICON%" --name="%NAME%" --add-data="%ICON%;." "%MAIN_SCRIPT%"
xcopy /E /I /Y lang "%FOLDER%\lang"
xcopy /E /I /Y theme "%FOLDER%\theme"
copy /Y TaskbarLib.tlb "%FOLDER%\"
powershell -Command "Compress-Archive -Path '%FOLDER%\*' -DestinationPath '%NAME%.zip' -Force"

pause