!macro NSIS_HOOK_POSTINSTALL
  WriteRegStr HKCU "Software\Classes\yousoro" "" "URL:Yousoro Workspace"
  WriteRegStr HKCU "Software\Classes\yousoro" "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\yousoro\shell\open\command" "" '"$INSTDIR\yousoro-workspace.exe" "%1"'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ReadRegStr $0 HKCU "Software\Classes\yousoro\shell\open\command" ""
  StrCmp $0 '"$INSTDIR\yousoro-workspace.exe" "%1"' 0 +2
    DeleteRegKey HKCU "Software\Classes\yousoro"
!macroend
