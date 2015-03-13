nmake clean
del *.exe
del *.dll
nmake all
copy evtcef.exe s:\Apps\EvtSys\x\
copy evtcef.dll s:\Apps\EvtSys\x\

