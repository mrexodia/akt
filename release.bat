@echo off
rmdir /S /Q release
mkdir release
mkdir release\plugins

copy bin\armabrut_opencl.dll release\
copy bin\armabrut_opencl.exe release\
copy bin\brute_opencl.cl release\
copy bin\BeaEngine.dll release\
copy bin\brute_dlp.dll release\
copy bin\brute_sym.dll release\
copy bin\TitanEngine.dll release\
copy bin\Armadillo_KeyTool.exe release\
copy bin\plugins\*.dll release\plugins\