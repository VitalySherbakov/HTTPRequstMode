@echo off
title Run VN Script
set path_env=venv\Scripts\activate
::cmd /k "%path_env% & python %script% PROXYCREAT proxy_list_new44.txt proxy.txt history_proxy.txt 0 0 0"
::cmd /k "%path_env% & python %script% PROXYCREAT freeproxy_2b3804d55151d00.txt proxy2.txt history_proxy2.txt 0 0 0"
::cmd /k "%path_env% & python %script% PROXYCREAT proxy_list_new44.txt proxy.txt history_proxy.txt 0 0 0 6"
::cmd /k "%path_env% & python %script% PROXYCREAT3 190.151.94.3 46615"
::cmd /k "%path_env% & python %script% PROXYCREAT2 freeproxy_2b3804d55151d00.txt proxy3.txt history_proxy3.txt 0 0 0 300"
::cmd /k "%path_env% & python %script% PEREVODTHREADSINHRON proxy3.txt lotr2.str lotr_rus.str en ru 0 800"
::cmd /k "%path_env% & python %script% PEREVODTHREAD proxy3.txt lotr2.str lotr_rus.str en ru 0 800"
::cmd /k "%path_env% & python %script% PEREVOD proxy3.txt lotr_edain_en.str lotr_edain_rus.str en ru 10 0"
::cmd /k "%path_env% & python %script% PAS lotr_rus2.str lotr.str lotr_pas_age.str"
::cmd /k "%path_env% & python %script% READ lotr3.str lotr4.str"
::cmd /k "%path_env% & python %script% FORMAT lotr_pas_age.str lotr_format_age.str"
::cmd /k "%path_env% & python %script% FORMAT lotr3.str lotr_format_age2.str"
::cmd /k "%path_env% & python %script% OST lotr_pas_age.str lotr.str lotr_ost_age.str"
python.exe Main.py
pause