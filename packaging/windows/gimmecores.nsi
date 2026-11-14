; GimmeCores installer for Windows (NSIS). Built by packaging/windows/build-installer.sh:
;   makensis -DVERSION=<x.y.z> -DSRC=<folder with the programs> -DOUTFILE=<setup.exe> -DICON=<.ico>
;
; Installs into Program Files (Windows asks for an administrator once): the app (GimmeCores.exe),
; gmcd and Microsoft's WebView2Loader.dll, the commands gmc and gimmecores in bin\ (on the PATH),
; a Start menu entry,
; an entry in Apps & features, and the firewall rules:
; incoming connections to gmcd only on private and work (domain) networks, refused on public
; networks (cafes, airports), so Windows never asks and lending cannot be reached there.
; The app is never started as administrator. The data folder (%LOCALAPPDATA%\GimmeCores: this
; device's identity, paired devices, settings) is kept on uninstall.

Unicode true
SetCompressor /SOLID lzma
!include "MUI2.nsh"

!define NAME "GimmeCores"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\GimmeCores"
!define RULE "GimmeCores (gmcd)"
!define RULE_PUBLIC "GimmeCores (gmcd), public networks"

Name "${NAME}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\GimmeCores"
RequestExecutionLevel admin
BrandingText "GimmeCores ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "GimmeCores"
VIAddVersionKey "FileDescription" "GimmeCores installer"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Apache License 2.0"

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_FINISHPAGE_TEXT "GimmeCores is installed. Open it from the Start menu and click Start GimmeCores. Lending stays off until you turn it on."
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetRegView 64
  SetShellVarContext all ; the Start menu entry is for every user
  ; An upgrade replaces running programs: stop them first (they start again from the app).
  nsExec::Exec 'taskkill /F /IM gmcd.exe'
  nsExec::Exec 'taskkill /F /IM GimmeCores.exe'
  Sleep 500

  ; The app and gmcd side by side (the app starts the gmcd next to it). The commands go in bin\,
  ; the folder put on the PATH: Windows names ignore case, so the command gimmecores.exe and the
  ; app GimmeCores.exe cannot share a folder.
  SetOutPath "$INSTDIR"
  File "/oname=GimmeCores.exe" "${SRC}\gimmecores-desktop.exe"
  File "${SRC}\gmcd.exe"
  File "${SRC}\WebView2Loader.dll"
  File "/oname=LICENSE.txt" "${SRC}\LICENSE"
  SetOutPath "$INSTDIR\bin"
  File "${SRC}\gmc.exe"
  File "${SRC}\gimmecores.exe"
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall GimmeCores.exe"

  CreateShortCut "$SMPROGRAMS\GimmeCores.lnk" "$INSTDIR\GimmeCores.exe"

  ; Firewall: allowed on private and work networks, refused on public ones.
  nsExec::Exec 'netsh advfirewall firewall delete rule name="${RULE}"'
  nsExec::Exec 'netsh advfirewall firewall delete rule name="${RULE_PUBLIC}"'
  nsExec::Exec 'netsh advfirewall firewall add rule name="${RULE}" dir=in action=allow program="$INSTDIR\gmcd.exe" enable=yes profile=private,domain'
  nsExec::Exec 'netsh advfirewall firewall add rule name="${RULE_PUBLIC}" dir=in action=block program="$INSTDIR\gmcd.exe" enable=yes profile=public'

  ; gmc on the PATH for every user (Windows tells running programs about the change).
  nsExec::Exec `powershell -NoProfile -ExecutionPolicy Bypass -Command "$$d='$INSTDIR\bin'; $$p=[Environment]::GetEnvironmentVariable('Path','Machine'); if (($$p -split ';') -notcontains $$d) { [Environment]::SetEnvironmentVariable('Path', $$p.TrimEnd(';') + ';' + $$d, 'Machine') }"`

  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "GimmeCores"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "GimmeCores"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "URLInfoAbout" "https://tanuj24.github.io/gimmecores/"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\GimmeCores.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\Uninstall GimmeCores.exe"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall GimmeCores.exe" /S'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all
  nsExec::Exec 'taskkill /F /IM gmcd.exe'
  nsExec::Exec 'taskkill /F /IM GimmeCores.exe'
  Sleep 500
  ; This user's start-at-sign-in entry (the app adds it).
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "GimmeCores"
  nsExec::Exec 'netsh advfirewall firewall delete rule name="${RULE}"'
  nsExec::Exec 'netsh advfirewall firewall delete rule name="${RULE_PUBLIC}"'
  nsExec::Exec `powershell -NoProfile -ExecutionPolicy Bypass -Command "$$d='$INSTDIR\bin'; $$p=[Environment]::GetEnvironmentVariable('Path','Machine'); [Environment]::SetEnvironmentVariable('Path', (($$p -split ';') | Where-Object { $$_ -and $$_ -ne $$d }) -join ';', 'Machine')"`

  Delete "$SMPROGRAMS\GimmeCores.lnk"
  Delete "$INSTDIR\GimmeCores.exe"
  Delete "$INSTDIR\gmcd.exe"
  Delete "$INSTDIR\bin\gmc.exe"
  Delete "$INSTDIR\bin\gimmecores.exe"
  RMDir "$INSTDIR\bin"
  Delete "$INSTDIR\WebView2Loader.dll"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\Uninstall GimmeCores.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
SectionEnd
