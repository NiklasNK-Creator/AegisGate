;; ============================================================================
;; AegisGate — Installer Script (NSIS)
;; Developer: Nik
;;
;; Builds AegisGate-Setup.exe — a one-click installer that:
;; 1. Requests admin rights (UAC prompt)
;; 2. Installs the AegisGate Agent to Program Files
;; 3. Disables Hyper-V automatically (bcdedit)
;; 4. Adds AegisGate to Windows startup (autostart)
;; 5. Creates Start Menu shortcuts
;; 6. Creates uninstaller
;; ============================================================================

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinVer.nsh"

;; ── General Settings ─────────────────────────────────────────────────────
Name "AegisGate"
OutFile "AegisGate-Setup.exe"
InstallDir "$PROGRAMFILES64\AegisGate"
InstallDirRegKey HKLM "Software\AegisGate" "InstallDir"
RequestExecutionLevel admin           ;; Force UAC elevation at start

;; ── Version Info ─────────────────────────────────────────────────────────
VIProductVersion "1.0.0.0"
VIAddVersionKey "ProductName" "AegisGate"
VIAddVersionKey "CompanyName" "Nik"
VIAddVersionKey "FileDescription" "AegisGate Hypervisor Security Gate Installer"
VIAddVersionKey "FileVersion" "1.0.0.0"
VIAddVersionKey "LegalCopyright" "Nik"

;; ── UI Settings ──────────────────────────────────────────────────────────
!define MUI_ABORTWARNING
!define MUI_ICON "resources\aegisgate.ico"
!define MUI_UNICON "resources\aegisgate.ico"
!define MUI_WELCOMEPAGE_TITLE "AegisGate Setup"
!define MUI_WELCOMEPAGE_TEXT "This will install AegisGate on your computer.$\r$\n$\r$\nAegisGate is a Ring -1 Hypervisor Security Gate that protects your system at the hardware level.$\r$\n$\r$\nThe installer will:$\r$\n  • Install the AegisGate Agent$\r$\n  • Disable Hyper-V (required)$\r$\n  • Add AegisGate to autostart$\r$\n$\r$\nA reboot will be required after installation."

;; ── Pages ────────────────────────────────────────────────────────────────
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "German"

;; ============================================================================
;;  Installation Section
;; ============================================================================

Section "AegisGate Agent" SecAgent
    SetOutPath "$INSTDIR"
    
    ;; Copy files
    File "bin\AegisGate.exe"
    File "resources\aegisgate.ico"
    File /oname=README.txt "..\README.md"
    
    ;; Write registry keys for uninstaller
    WriteRegStr HKLM "Software\AegisGate" "InstallDir" "$INSTDIR"
    WriteRegStr HKLM "Software\AegisGate" "Version" "1.0.0"
    
    ;; Add/Remove Programs entry
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisGate" \
        "DisplayName" "AegisGate"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisGate" \
        "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisGate" \
        "DisplayIcon" '"$INSTDIR\aegisgate.ico"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisGate" \
        "Publisher" "Nik"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisGate" \
        "DisplayVersion" "1.0.0"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisGate" \
        "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisGate" \
        "NoRepair" 1
    
    ;; Create uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    
    ;; Create Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\AegisGate"
    CreateShortCut "$SMPROGRAMS\AegisGate\AegisGate.lnk" "$INSTDIR\AegisGate.exe" \
        "" "$INSTDIR\aegisgate.ico"
    CreateShortCut "$SMPROGRAMS\AegisGate\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

;; ============================================================================
;;  Autostart Section
;; ============================================================================

Section "Autostart" SecAutostart
    ;; Add to Windows startup via registry
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" \
        "AegisGate" '"$INSTDIR\AegisGate.exe"'
SectionEnd

;; ============================================================================
;;  System Configuration Section
;; ============================================================================

Section "System Setup" SecSystem
    ;; ── Disable Hyper-V ──────────────────────────────────────────────
    DetailPrint "Disabling Hyper-V..."
    nsExec::ExecToLog 'bcdedit /set hypervisorlaunchtype off'
    Pop $0
    ${If} $0 == 0
        DetailPrint "Hyper-V disabled successfully."
    ${Else}
        DetailPrint "Note: Hyper-V was already disabled or not installed."
    ${EndIf}
    
    ;; ── Disable Device Guard / Credential Guard ──────────────────────
    DetailPrint "Checking Device Guard..."
    nsExec::ExecToLog 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity'
    Pop $0
    ${If} $0 == 0
        DetailPrint "Disabling Virtualization-Based Security..."
        nsExec::ExecToLog 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f'
    ${EndIf}
    
    ;; ── Disable Windows Sandbox (if enabled) ─────────────────────────
    DetailPrint "Checking Windows Sandbox..."
    nsExec::ExecToLog 'dism /online /get-featureinfo /featurename:Containers-DisposableClientVM'
    Pop $0
    
    ;; ── Prompt for reboot ────────────────────────────────────────────
    MessageBox MB_YESNO|MB_ICONQUESTION \
        "AegisGate has been installed successfully!$\r$\n$\r$\nA system restart is required for Hyper-V changes to take effect.$\r$\n$\r$\nRestart now?" \
        IDYES reboot IDNO done
    
    reboot:
        Reboot
    done:
SectionEnd

;; ============================================================================
;;  Uninstall Section
;; ============================================================================

Section "Uninstall"
    ;; Remove autostart
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "AegisGate"
    
    ;; Remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisGate"
    DeleteRegKey HKLM "Software\AegisGate"
    
    ;; Remove files
    Delete "$INSTDIR\AegisGate.exe"
    Delete "$INSTDIR\aegisgate.ico"
    Delete "$INSTDIR\README.txt"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"
    
    ;; Remove Start Menu shortcuts
    Delete "$SMPROGRAMS\AegisGate\AegisGate.lnk"
    Delete "$SMPROGRAMS\AegisGate\Uninstall.lnk"
    RMDir "$SMPROGRAMS\AegisGate"
    
    ;; Re-enable Hyper-V (optional — ask user)
    MessageBox MB_YESNO|MB_ICONQUESTION \
        "Do you want to re-enable Hyper-V?$\r$\n(Only needed if you use WSL2, Docker, or Windows Sandbox)" \
        IDYES reenable IDNO skip_hv
    
    reenable:
        nsExec::ExecToLog 'bcdedit /set hypervisorlaunchtype auto'
    skip_hv:
SectionEnd
