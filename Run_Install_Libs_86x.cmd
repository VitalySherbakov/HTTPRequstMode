@echo off
:start
title Libs Install
set file=requirements.txt
echo FILE INSTALL: %file%
title Libs Install %file%
c:\Python38-32\Scripts\pip install -r %file%
pause
goto start
pause