# Installing SecureMusic USB

SecureMusic USB is currently a desktop application. Builds must be created separately for each operating system; a Windows executable does not run natively on Android, iOS, macOS, or Linux.

## Download a build

1. Open the repository's **Actions** tab.
2. Select **Build desktop installers** and choose **Run workflow**, or push a version tag such as `v1.0.1`.
3. Wait for all test-and-build jobs to finish successfully.
4. Open the completed workflow run and download the artifact for your operating system:
   - `SecureMusicUSB-Windows`
   - `SecureMusicUSB-macOS`
   - `SecureMusicUSB-Linux`

Artifacts from a manual workflow run are temporary (14 days). This workflow currently uploads Actions artifacts; it does not yet publish a GitHub Release.

## Run from source on Windows

Install Python 3.10+ from python.org, then open PowerShell in the repository directory:

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python securemusic_usb.py
```

## Important device compatibility

- Windows, macOS, and Linux desktop builds are separate native artifacts.
- This Python/Tkinter application is **not an Android or iOS app**. Mobile support requires a separate native application and platform-specific secure-storage design.
- Car stereos, TVs, and other USB media players generally cannot read the encrypted `.smusb` vault. They need a normal audio file.
- The app cannot prevent someone from formatting the physical USB drive outside the app.
- Keep an independent backup of the original song and encrypted vault. Never format the drive as part of setup.

## Trust and security

The CI workflow runs the repository tests before packaging. A successful build is not a code-signing certificate or a security audit. Windows SmartScreen and macOS Gatekeeper may warn about unsigned binaries. Do not enter your vault password into any third-party installer or website.
