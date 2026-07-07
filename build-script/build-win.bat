:: --windowed builds a no-console executable. The app defaults to tray mode when
:: frozen, so lan-clip.exe is double-clickable and runs silently in the tray with no
:: console to hide. This removes the need for traymode.vbs (a hidden-window VBS
:: launcher that AV engines flagged).
pyinstaller --name=lan-clip --windowed --add-data "templates;templates" --add-data "static;static" --version-file build-script\version_info.txt --log-level WARN app.py -y

echo Build complete in batch script. (No pause, returning to PowerShell)