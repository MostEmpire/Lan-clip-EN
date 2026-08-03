# LAN Clipboard
This software solves the following main problems:
- Easily share images across devices on the local network
- Easily share big files across devices on the local network
- Easily share text across devices. Paste on one device, copy on another
- Share image snippets with automatic configurable image compression

<img width="1257" height="902" alt="image" src=".github/app_look_1_1_1.jpg" />

Highlights
- Supports text / image / file storage
- Automatically detects and converts URLs into hyperlinks
- High-speed transfer over the local network
- Windows tray mode
- Synchronized refresh across multiple devices
- Delete-all password: 1230 (can be changed in pwd.txt)
- Permission management: pinning, editing, and deleting posts require a password. (can be changed in pwd.txt)

## Shortcut Mode
You'll notice a small panel selection icon in the top-right corner. This is shortcut mode, which you can enable by clicking the button or pressing the Down arrow key in a blank area.
Once enabled, a card is selected. You can move with the arrow keys, c to copy, Enter to open the link/image, d to download, and Del to delete.
Batch deletion is very handy. No more aiming the mouse to click buttons.
<img width="1353" height="908" alt="Shortcut mode" src=".github/shortcut_mode_v3.jpg" />


## Clipboard Monitoring Mode
The packaged executable starts in tray mode by default. When running from source, clipboard monitoring mode can be started with the --tray argument (use --no-tray to run the web server only).
Once enabled, a small green lizard appears in the tray. Right-click to start monitoring, and clipboard contents are automatically added to lan-clip.
- Windows users can launch it by simply double-clicking lan-clip.exe from the release — it runs silently in the tray (no console window).
- Mac users can ask an AI how to write a hidden launch command. Write your own and add it to your .zshrc file. For example: `alias lanclip="cd /Users/kasusa/Documents/GitHub/Lan-clip; nohup python3 app.py --tray > /dev/null 2>&1 &"`
- Linux users may need to modify tray_manager.py and run from the Python source code, since I've only tested the Windows and Mac versions.

<img width="630" height="237" alt="image" src=".github/traymode_v1.jpg" />



# Installation and Startup
1. Windows desktop version

> Download the exe file from the Release page

2. Docker deployment (server)
bash

## Docker Hub Image
```bash
# Basic startup
docker run -d -p 5000:5000 kasusa/lan-clip:latest

# Persistent startup (recommended)
# Note: Before running, manually create the files, otherwise Docker will mistake them for directories and throw an error
sudo mkdir -p LAN-clip/cards LAN-clip/uploads LAN-clip/images
sudo touch LAN-clip/pwd.txt
echo "[]" | sudo tee LAN-clip/pinned.json
sudo chmod 777 LAN-clip

docker run -d -p 5000:5000 \
  -v $(pwd)/LAN-clip/cards:/app/cards \
  -v $(pwd)/LAN-clip/uploads:/app/uploads \
  -v $(pwd)/LAN-clip/images:/app/images \
  -v $(pwd)/LAN-clip/pinned.json:/app/pinned.json \
  -v $(pwd)/LAN-clip/pwd.txt:/app/pwd.txt \
  kasusa/lan-clip:latest
```

3. Run from source
```
python app.py
python app.py --tray # clipboard monitoring mode
```

## Changelog
2026-08-03
- Implemented https support into the application
- Fixed UnicodeEncodeError occurring when banner message was printed in the console
- Fixed a problem for macOS, where mDNS window was not usable
- Added mDNS watchdog that tries to recover from mDNS failures
- Fixed mDNS Discovery problem where the app advertised only to one adapter (may not have been the one in use)

2026-07-07
- The application now runs in tray mode by default (trust increase)
- Added mDNS feature to the application, so that other users on the network can more easily connect to the web interface

2026-06-27
- Added background switching feature

2026-06-15
- Implemented better use of the space in the text input bubble.
- Added Paste-from-clipboard feature.

2026-06-02
- Changed some User Interface things (app is translated to english, scroll to home reorganization, input field split into text, image and files, and some more).
- Implemented Keep for a time (autodelete) feature.
- Implemented live refresh.

2026-02-28
- Added a permission management feature; pinning, editing, and deleting posts require a password. (can be changed in pwd.txt)

2026-02-28 10:24:46
- Added download and delete buttons to each image in the gallery preview
- Added a "Settings → Compact mode" toggle to switch between experiences: normal mode keeps animations and large image previews, while compact mode is flatter, scrolls faster, and makes action buttons more prominent.
- Upload progress bar; a progress indicator is shown for files larger than UPLOAD_PROGRESS_MIN_SIZE
- Added password setting via pwd.txt
- Delete animation
- Double-click a card to enter highlight-card mode; use the arrow keys to move the selection, del/backspace to delete (after deleting, the next card is selected automatically), d to download, e to edit, c to copy (these only work while a card is highlighted)

2026-01-17
- Allow pinning cards
- No longer freezes the background when refreshing
- Added docker -v volume mounting for persistence