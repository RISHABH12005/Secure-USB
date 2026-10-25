#define MyAppName "SecureUSB"
#define MyAppVersion "1.0.0"
#define MyPublisher "SecureUSB"
#define MyExeName "SecureUSB.exe"

[Setup]
AppId={{A4DCA7B9-76B7-4A20-A7E2-4FBD7E9D1134}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyPublisher}
DefaultDirName={autopf}\SecureUSB
DefaultGroupName={#MyAppName}
OutputDir=output
OutputBaseFilename=SecureUSB-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\{#MyExeName}
SetupLogging=yes

[Files]
Source: "..\dist\{#MyExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Run]
Filename: "{app}\{#MyExeName}"; Description: "Launch {#MyAppName}"; Flags: postinstall nowait skipifsilent
