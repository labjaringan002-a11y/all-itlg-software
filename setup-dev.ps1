<#
 setup-dev.ps1  (v2)
 Untuk komputer Windows kosong. Script ini akan, untuk tiap software:
   1. Download installer dari server resmi
   2. Verifikasi integritas (hash dari server resmi / hash yang diketahui / tanda tangan digital)
   3. Install secara silent (tanpa klik-klik)
   4. Refresh PATH di sesi ini (tanpa perlu restart terminal)
 Lalu menampilkan tabel versi semua tool.

 Cara pakai: klik dua kali jalankan.bat  (atau: powershell -ExecutionPolicy Bypass -File setup-dev.ps1)
 Opsi: -SkipHash  melewati semua verifikasi (tidak disarankan)

 Yang TIDAK bisa otomatis: Cisco Packet Tracer (butuh login NetAcad).
#>
param([switch]$SkipHash)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # Invoke-WebRequest jauh lebih cepat tanpa progress bar
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Minta hak Administrator kalau belum ------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Meminta hak Administrator..." -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($SkipHash) { $argList += '-SkipHash' }
    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit
}

$InstallDir = Join-Path $PSScriptRoot 'installers'
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Ubah di sini kalau mau versi Fuseki lain (6.1.0 sudah masuk arsip Apache; versi terbaru saat ini 6.2.0)
$FusekiVersion = '6.1.0'

$Unverified = New-Object System.Collections.ArrayList

# =============================================================================
# Fungsi bantu
# =============================================================================
function Say([string]$msg, [string]$color = 'Gray') { Write-Host "  $msg" -ForegroundColor $color }

function Update-SessionPath {
    # Setara dengan "restart terminal": baca ulang PATH dari registry
    $m = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$m;$u"
    $jh = [Environment]::GetEnvironmentVariable('JAVA_HOME', 'Machine')
    if ($jh) { $env:JAVA_HOME = $jh }
}

function Add-MachinePath([string]$dir) {
    if (-not (Test-Path $dir)) { return }
    $parts = ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') | Where-Object { $_ }
    if ($parts -notcontains $dir) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $dir) -join ';'), 'Machine')
        Say "PATH += $dir"
    }
}

function Get-FileVer([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    $v = (Get-Item $path).VersionInfo.ProductVersion
    if ($v) { return "$v" } else { return 'terpasang' }
}

function Get-Version($check) {
    # Kembalikan teks versi, atau $null kalau tool tidak ada
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # java -version menulis ke stderr
    try {
        if ($check.Test) {
            $r = & $check.Test
            if ($r) { return "$r" } else { return $null }
        }
        $cmd = Get-Command $check.Exe -ErrorAction SilentlyContinue
        if (-not $cmd -or $cmd.Source -match 'WindowsApps') { return $null }   # abaikan stub Microsoft Store
        $exeArgs = @($check.Args)
        $out = & $check.Exe @exeArgs 2>&1 | ForEach-Object { "$_" } | Select-Object -First 1
        if ($LASTEXITCODE -ne 0) { return $null }
        return $out
    } catch { return $null }
    finally { $ErrorActionPreference = $old }
}

function Get-GitHubAsset([string]$repo, [string]$pattern) {
    $headers = @{ 'User-Agent' = 'setup-dev'; 'Accept' = 'application/vnd.github+json' }
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers $headers
    $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
    if (-not $asset) { throw "Asset '$pattern' tidak ada di $repo. Yang tersedia: $(($rel.assets | ForEach-Object { $_.name }) -join ', ')" }
    $sha = $null
    if ($asset.digest -and "$($asset.digest)" -like 'sha256:*') { $sha = "$($asset.digest)".Substring(7) }
    return @{ Url = $asset.browser_download_url; File = $asset.name; Sha = $sha; Version = $rel.tag_name }
}

function Test-Signature([string]$path) {
    $sig = Get-AuthenticodeSignature -FilePath $path
    if ($sig.Status -eq 'Valid') { return $sig.SignerCertificate.Subject }
    return $null
}

function Confirm-File($item, [string]$path) {
    # Hasil: SKIP | HASH | SIGNED | NONE | MISMATCH
    if ($SkipHash) { return 'SKIP' }
    $algo = 'SHA256'
    if ($item.Algo) { $algo = $item.Algo }
    $len = @{ MD5 = 32; SHA256 = 64; SHA512 = 128 }[$algo]
    $expected = $null

    foreach ($u in @($item.ShaUrls)) {
        if (-not $u) { continue }
        try {
            $txt = (Invoke-WebRequest -Uri $u -UseBasicParsing).Content
            if ($txt -is [byte[]]) { $txt = [Text.Encoding]::UTF8.GetString($txt) }
            $pattern = "(?i)\b[0-9a-f]{$len}\b"
            $line = ($txt -split "`n" | Where-Object { $_ -match [regex]::Escape($item.File) } | Select-Object -First 1)
            if ($line) {
                $m = [regex]::Match($line, $pattern)
                if ($m.Success) { $expected = $m.Value.ToLower() }
            } else {
                $all = [regex]::Matches($txt, $pattern)
                if ($all.Count -eq 1) { $expected = $all[0].Value.ToLower() }
            }
            if ($expected) { Say "Hash diambil dari server resmi: $u"; break }
        } catch { Say "Tidak bisa ambil hash dari $u" Yellow }
    }
    if (-not $expected -and $item.Sha) { $expected = "$($item.Sha)".ToLower() }

    if ($expected) {
        $actual = (Get-FileHash -Algorithm $algo -Path $path).Hash.ToLower()
        if ($actual -eq $expected) { return 'HASH' } else { return 'MISMATCH' }
    }
    if (@('exe', 'msi') -contains $item.Type) {
        if (Test-Signature $path) { return 'SIGNED' }
    }
    return 'NONE'
}

function Resolve-Item($item) {
    if ($item.Resolve) {
        $r = & $item.Resolve
        foreach ($k in $r.Keys) { $item[$k] = $r[$k] }
        if ($r.Url) { $item.Urls = @($r.Url) }
    }
}

function Get-Installer($item) {
    Resolve-Item $item
    $path = Join-Path $InstallDir $item.File

    if (Test-Path $path) {
        $res = Confirm-File $item $path
        if ($res -ne 'MISMATCH') {
            Say "Pakai file lokal: $($item.File)" Green
            if ($res -eq 'NONE') { [void]$Unverified.Add($item.Name) }
            return $path
        }
        Say 'File lokal tidak cocok dengan hash, download ulang.' Yellow
        Remove-Item $path -Force
    }

    $part = "$path.part"
    $ok = $false
    foreach ($url in $item.Urls) {
        for ($try = 1; $try -le 3 -and -not $ok; $try++) {
            try {
                Say "Download ($try/3): $url"
                Invoke-WebRequest -Uri $url -OutFile $part -UseBasicParsing
                $ok = $true
            } catch {
                Say "Gagal: $($_.Exception.Message)" Yellow
                Start-Sleep -Seconds 3
            }
        }
        if ($ok) { break }
    }
    if (-not $ok) { throw 'Semua URL download gagal.' }

    $res = Confirm-File $item $part
    switch ($res) {
        'MISMATCH' {
            Remove-Item $part -Force
            throw 'Hash TIDAK cocok. File dibuang demi keamanan (pakai -SkipHash hanya kalau yakin).'
        }
        'HASH'   { Say 'Hash cocok.' Green }
        'SIGNED' { Say 'Tidak ada hash, tapi tanda tangan digital valid.' Green }
        'SKIP'   { Say 'Verifikasi dilewati (-SkipHash).' Yellow }
        'NONE'   { Say 'PERINGATAN: tidak ada hash/tanda tangan untuk verifikasi (download via HTTPS dari situs resmi).' Yellow; [void]$Unverified.Add($item.Name) }
    }
    Move-Item $part $path -Force
    return $path
}

function Expand-Zip([string]$zip, [string]$dest) {
    if ((Test-Path $dest) -and (Get-ChildItem $dest -Force -ErrorAction SilentlyContinue | Select-Object -First 1)) {
        throw "Folder $dest sudah ada isinya. Hapus/pindahkan dulu lalu jalankan ulang."
    }
    $tmp = Join-Path $env:TEMP ('x_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        if (Get-Command tar.exe -ErrorAction SilentlyContinue) {
            & tar.exe -xf $zip -C $tmp
            if ($LASTEXITCODE -ne 0) { throw 'tar gagal mengekstrak zip.' }
        } else {
            Expand-Archive -Path $zip -DestinationPath $tmp -Force
        }
        $inner = @(Get-ChildItem $tmp -Force)
        $src = $tmp
        if ($inner.Count -eq 1 -and $inner[0].PSIsContainer) { $src = $inner[0].FullName }   # buang folder pembungkus
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Get-ChildItem $src -Force | Move-Item -Destination $dest -Force
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Install-Item($item, [string]$path) {
    $a = ''
    if ($item.Args -is [scriptblock]) { $a = & $item.Args } elseif ($item.Args) { $a = [string]$item.Args }

    if ($item.Type -eq 'zip') {
        Expand-Zip $path $item.Dest
        return
    }
    if ($item.Type -eq 'msi') {
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$path`" $a /qn /norestart" -Wait -PassThru
    } else {
        $p = Start-Process -FilePath $path -ArgumentList $a -Wait -PassThru
    }
    # 0 = sukses, 3010/1641 = sukses tapi minta reboot
    $okCodes = @(0, 3010, 1641)
    if ($item.OkCodes) { $okCodes += $item.OkCodes }
    if ($okCodes -notcontains $p.ExitCode) { throw "Installer keluar dengan kode $($p.ExitCode)" }
    if ($p.ExitCode -in 3010, 1641) { Say "Windows meminta reboot (kode $($p.ExitCode)), biasanya tidak perlu untuk memakai tool ini." Yellow }
}

# =============================================================================
# Daftar software (urutan penting: Laragon sebelum Composer, Java sebelum Fuseki)
# =============================================================================
$Items = @(
    # ---------------- Dasar ----------------
    @{
        Name  = 'Visual C++ Redistributable 2015-2022 (x64)'
        File  = 'vc_redist.x64.exe'
        Urls  = @('https://aka.ms/vs/17/release/vc_redist.x64.exe')
        Type  = 'exe'
        Args  = '/install /quiet /norestart'
        OkCodes = @(1638)   # 1638 = versi yang sama/lebih baru sudah ada
        Checks = @(@{ Label = 'vc++ redist'; Test = {
            $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -ErrorAction SilentlyContinue
            if ($k -and $k.Installed -eq 1) { "$($k.Version)" }
        } })
    },

    # ---------------- Bahasa pemrograman ----------------
    @{
        Name  = 'Python 3.14.10'
        File  = 'python-3.14.10-amd64.exe'
        Urls  = @('https://www.python.org/ftp/python/3.14.10/python-3.14.10-amd64.exe')
        Sha   = '92480239264744fe0386a1bd8275786fefa126e3129e56a68e22b52c73329965'
        Type  = 'exe'
        Args  = '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0'
        Checks = @(@{ Label = 'python'; Exe = 'python'; Args = @('--version') })
    },
    @{
        Name  = 'Node.js 26.13.0'
        File  = 'node-v26.13.0-x64.msi'
        Urls  = @('https://nodejs.org/dist/v26.13.0/node-v26.13.0-x64.msi')
        Sha   = '0e5ee99c7cbf922887f04af268e3665990748945336a44956f47cc0df695b6df'
        Type  = 'msi'
        Checks = @(
            @{ Label = 'node'; Exe = 'node'; Args = @('--version') },
            @{ Label = 'npm';  Exe = 'npm';  Args = @('--version') }
        )
    },
    @{
        Name  = 'OpenJDK 25.0.5 (Temurin)'
        File  = 'OpenJDK25U-jdk_x64_windows_hotspot_25.0.5_8.msi'
        Urls  = @('https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_windows_hotspot_25.0.5_8.msi')
        Sha   = 'e1d3c94032579dc16af9abb311f4552ba271466b74c8767e8ce39585a4c64d40'
        Type  = 'msi'
        Args  = 'ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJavaHome'
        Checks = @(
            @{ Label = 'javac'; Exe = 'javac'; Args = @('-version') },
            @{ Label = 'java';  Exe = 'java';  Args = @('-version') }
        )
    },
    @{
        Name  = 'SWI-Prolog 10.0.2'
        File  = 'swipl-10.0.2-1.x64.exe'
        Urls  = @('https://www.swi-prolog.org/download/stable/bin/swipl-10.0.2-1.x64.exe')
        Sha   = '2ec1f25be0eafb92e559004782b130774c12573fb4b7e8a917e534754a641ad6'
        Type  = 'exe'
        Args  = '/S'
        PathDirs = @("$env:ProgramFiles\swipl\bin")
        Checks = @(@{ Label = 'swipl'; Exe = 'swipl'; Args = @('--version') })
    },
    @{
        Name  = 'Free Pascal 3.2.2'
        File  = 'fpc-3.2.2.win32.and.win64.exe'
        Urls  = @(
            'https://downloads.freepascal.org/fpc/dist/3.2.2/i386-win32/fpc-3.2.2.win32.and.win64.exe',
            'https://sourceforge.net/projects/freepascal/files/Win32/3.2.2/fpc-3.2.2.win32.and.win64.exe/download'
        )
        Sha   = '8c255390544b051388b577eb61c6191a04883264afe0e3369b3600a56daf7bde'
        Type  = 'exe'
        Args  = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-'
        PathDirs = @('C:\FPC\3.2.2\bin\i386-win32')
        Checks = @(@{ Label = 'fpc'; Exe = 'fpc'; Args = @('-iV') })
    },
    @{
        Name  = 'MSYS2 + GCC (C/C++)'
        File  = 'msys2-x86_64-20260927.exe'
        Urls  = @('https://github.com/msys2/msys2-installer/releases/download/2026-09-27/msys2-x86_64-20260927.exe')
        Sha   = '416d506c839a2da4bc184eeec8cbaaf1055ee698618228c62dfc4232a6970f0e'
        Type  = 'exe'
        Args  = 'in --confirm-command --accept-messages --root C:/msys64'
        PathDirs = @('C:\msys64\ucrt64\bin')
        Post  = {
            param($item)
            $bash = 'C:\msys64\usr\bin\bash.exe'
            Say 'Update database pacman (bisa lama, 2 putaran)...'
            & $bash -lc 'pacman -Syu --noconfirm'
            & $bash -lc 'pacman -Syu --noconfirm'
            Say 'Memasang GCC...'
            & $bash -lc 'pacman -S --needed --noconfirm mingw-w64-ucrt-x86_64-gcc'
        }
        Checks = @(@{ Label = 'gcc'; Exe = 'gcc'; Args = @('--version') })
    },

    # ---------------- Web & Database ----------------
    @{
        Name  = 'Laragon (terbaru, PHP 8.5)'
        File  = 'laragon-wamp.exe'
        Resolve = {
            try { Get-GitHubAsset 'leokhoa/laragon' '^laragon-wamp\.exe$' }
            catch { @{ Url = 'https://github.com/leokhoa/laragon/releases/latest/download/laragon-wamp.exe'; File = 'laragon-wamp.exe' } }
        }
        Type  = 'exe'
        Args  = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
        Post  = {
            param($item)
            $php = Get-ChildItem 'C:\laragon\bin\php' -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
            if ($php) { Add-MachinePath $php.FullName }
        }
        Checks = @(
            @{ Label = 'laragon'; Test = { Get-FileVer 'C:\laragon\laragon.exe' } },
            @{ Label = 'php';     Exe = 'php'; Args = @('-v') }
        )
    },
    @{
        Name  = 'Composer 2.x (terbaru)'
        File  = 'Composer-Setup.exe'
        Urls  = @('https://getcomposer.org/Composer-Setup.exe')
        Type  = 'exe'
        Args  = {
            $php = Get-ChildItem 'C:\laragon\bin\php' -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
            if (-not $php) { throw 'PHP milik Laragon tidak ditemukan (C:\laragon\bin\php). Pastikan Laragon terpasang dulu.' }
            "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /PHP=`"$($php.FullName)`""
        }
        PathDirs = @('C:\ProgramData\ComposerSetup\bin')
        Checks = @(@{ Label = 'composer'; Exe = 'composer'; Args = @('--version') })
    },
    @{
        Name  = 'MySQL 9.7.2 LTS (service: MySQL97, root tanpa password)'
        File  = 'mysql-9.7.2-winx64.zip'
        Urls  = @(
            'https://cdn.mysql.com/Downloads/MySQL-9.7/mysql-9.7.2-winx64.zip',
            'https://downloads.mysql.com/archives/get/p/23/file/mysql-9.7.2-winx64.zip'
        )
        Algo  = 'MD5'
        Sha   = '657957207455a6a5b072f0d6cd1900a9'
        Type  = 'zip'
        Dest  = 'C:\mysql'
        PathDirs = @('C:\mysql\bin')
        Post  = {
            param($item)
            $base = 'C:\mysql'
            $ini = @('[mysqld]', 'basedir=C:/mysql', 'datadir=C:/mysql/data', 'port=3306', 'bind-address=127.0.0.1') -join "`r`n"
            Set-Content -Path "$base\my.ini" -Value $ini -Encoding ASCII
            Say 'Inisialisasi data MySQL (root tanpa password)...'
            & "$base\bin\mysqld.exe" --defaults-file="$base\my.ini" --initialize-insecure --console
            if ($LASTEXITCODE -ne 0) { throw 'mysqld --initialize-insecure gagal.' }
            & "$base\bin\mysqld.exe" --install MySQL97 --defaults-file="$base\my.ini"
            if ($LASTEXITCODE -ne 0) { throw 'mysqld --install gagal.' }
            Start-Service MySQL97
        }
        Checks = @(@{ Label = 'mysql'; Exe = 'mysql'; Args = @('--version') })
    },
    @{
        Name  = 'Postman (terbaru)'
        File  = 'Postman-win64-latest.exe'
        Urls  = @('https://dl.pstmn.io/download/latest/win64')
        Type  = 'exe'
        Args  = '-s'
        Checks = @(@{ Label = 'postman'; Test = { Get-FileVer "$env:LOCALAPPDATA\Postman\Postman.exe" } })
    },

    # ---------------- Web Semantik ----------------
    @{
        Name  = "Apache Jena Fuseki $FusekiVersion (butuh Java 21+)"
        File  = "apache-jena-fuseki-$FusekiVersion.zip"
        Urls  = @(
            "https://dlcdn.apache.org/jena/binaries/apache-jena-fuseki-$FusekiVersion.zip",
            "https://archive.apache.org/dist/jena/binaries/apache-jena-fuseki-$FusekiVersion.zip"
        )
        ShaUrls = @(
            "https://downloads.apache.org/jena/binaries/apache-jena-fuseki-$FusekiVersion.zip.sha512",
            "https://archive.apache.org/dist/jena/binaries/apache-jena-fuseki-$FusekiVersion.zip.sha512"
        )
        Algo  = 'SHA512'
        Type  = 'zip'
        Dest  = 'C:\tools\fuseki'
        Post  = {
            param($item)
            Set-Content 'C:\tools\fuseki\.installed-version' $FusekiVersion -Encoding ASCII
            [Environment]::SetEnvironmentVariable('FUSEKI_HOME', 'C:\tools\fuseki', 'Machine')
        }
        Checks = @(@{ Label = 'fuseki'; Test = {
            if ((Test-Path 'C:\tools\fuseki\fuseki-server.bat') -or (Test-Path 'C:\tools\fuseki\fuseki-server.jar')) {
                $v = Get-Content 'C:\tools\fuseki\.installed-version' -ErrorAction SilentlyContinue
                if ($v) { "Fuseki $v (C:\tools\fuseki)" } else { 'terpasang (C:\tools\fuseki)' }
            }
        } })
    },
    @{
        Name  = 'Protege 5.6.x (stable terbaru)'
        File  = 'Protege-win.zip'
        Resolve = { Get-GitHubAsset 'protegeproject/protege-distribution' '^Protege-[\d\.]+-win\.zip$' }
        Type  = 'zip'
        Dest  = 'C:\tools\Protege'
        Post  = {
            param($item)
            Set-Content 'C:\tools\Protege\.installed-version' ($item.Version -replace '^protege-', '') -Encoding ASCII
            $exe = Get-ChildItem 'C:\tools\Protege' -Recurse -Filter 'Protege.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($exe) {
                $w = New-Object -ComObject WScript.Shell
                $s = $w.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Protege.lnk")
                $s.TargetPath = $exe.FullName
                $s.WorkingDirectory = $exe.DirectoryName
                $s.Save()
                Say 'Shortcut Start Menu dibuat: Protege'
            }
        }
        Checks = @(@{ Label = 'protege'; Test = {
            if (Test-Path 'C:\tools\Protege\.installed-version') { "Protege $(Get-Content 'C:\tools\Protege\.installed-version') (C:\tools\Protege)" }
        } })
    },

    # ---------------- Lainnya ----------------
    @{
        Name  = 'Blender 5.2.0 LTS'
        File  = 'blender-5.2.0-windows-x64.msi'
        Urls  = @('https://download.blender.org/release/Blender5.2/blender-5.2.0-windows-x64.msi')
        ShaUrls = @('https://download.blender.org/release/Blender5.2/blender-5.2.0.sha256')
        Sha   = '8ba59aed79dfc35d65c5e9e0ccc828d618796499483ccdeee0b534a915140606'
        Type  = 'msi'
        Checks = @(@{ Label = 'blender'; Test = {
            $p = Get-ChildItem "$env:ProgramFiles\Blender Foundation\Blender *\blender.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($p) {
                $v = & $p.FullName --version 2>&1 | ForEach-Object { "$_" } | Select-Object -First 1
                if ($v) { $v } else { 'terpasang' }
            }
        } })
    },
    @{
        Name  = 'Android Studio Rabbit 2 | 2026.2.2 Patch 1 (1.5 GB)'
        File  = 'android-studio-rabbit2-patch1-windows.exe'
        Urls  = @(
            'https://edgedl.me.gvt1.com/android/studio/install/2026.2.2.9/android-studio-rabbit2-patch1-windows.exe',
            'https://redirector.gvt1.com/edgedl/android/studio/install/2026.2.2.9/android-studio-rabbit2-patch1-windows.exe'
        )
        Sha   = '00e98c1c23e1d27a8079951291d1ae310bbc8c7ef1030ab9db1f45a1bb96543b'
        Type  = 'exe'
        Args  = '/S'
        Checks = @(@{ Label = 'android studio'; Test = {
            $d = "$env:ProgramFiles\Android\Android Studio"
            if (Test-Path "$d\bin\studio64.exe") {
                $j = $null
                try { $j = Get-Content "$d\product-info.json" -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
                if ($j -and $j.version) { "Android Studio $($j.version)" } else { 'terpasang' }
            }
        } })
    }
)

# =============================================================================
# Proses utama
# =============================================================================
$failed = @()
$total = $Items.Count
$n = 0
foreach ($item in $Items) {
    $n++
    Write-Host "`n=== [$n/$total] $($item.Name) ===" -ForegroundColor Cyan
    try {
        Update-SessionPath
        if (Get-Version $item.Checks[0]) { Say 'Sudah terpasang, dilewati.' Green; continue }

        $path = Get-Installer $item
        Say 'Memasang (silent)...'
        Install-Item $item $path

        foreach ($d in $item.PathDirs) { Add-MachinePath $d }
        if ($item.Post) { & $item.Post $item }
        foreach ($d in $item.PathDirs) { Add-MachinePath $d }
        Update-SessionPath

        # Beberapa installer (mis. Postman) kembali sebelum benar-benar selesai: tunggu sebentar
        for ($i = 0; $i -lt 20 -and -not (Get-Version $item.Checks[0]); $i++) { Start-Sleep -Seconds 3; Update-SessionPath }
        if (Get-Version $item.Checks[0]) { Say 'Selesai.' Green }
        else { Say 'Installer selesai, tapi tool belum terdeteksi. Cek tabel di bawah.' Yellow }
    } catch {
        Say "GAGAL: $($_.Exception.Message)" Red
        $failed += $item.Name
    }
}

# =============================================================================
# Cek versi (PATH sudah di-refresh, tidak perlu restart)
# =============================================================================
Write-Host "`n=== Hasil pengecekan versi ===" -ForegroundColor Cyan
Update-SessionPath
$rows = foreach ($item in $Items) {
    foreach ($c in $item.Checks) {
        $v = Get-Version $c
        [pscustomobject]@{
            Tool   = $c.Label
            Status = $(if ($v) { 'OK' } else { 'TIDAK ADA' })
            Versi  = $(if ($v) { $v } else { '-' })
        }
    }
}
$rows | Format-Table -AutoSize

if ($Unverified.Count -gt 0) {
    Write-Host "Tidak ada hash/tanda tangan untuk: $($Unverified -join ', ') (diunduh via HTTPS dari situs resmi)." -ForegroundColor Yellow
}
if ($failed.Count -gt 0) {
    Write-Host "Yang gagal: $($failed -join '; ')" -ForegroundColor Red
    Write-Host 'Jalankan ulang script ini; yang sudah terpasang akan dilewati.' -ForegroundColor Yellow
} else {
    Write-Host 'Semua tool terpasang. Terminal baru otomatis ikut punya PATH yang benar.' -ForegroundColor Green
}
Write-Host ''
Write-Host 'Catatan manual:' -ForegroundColor Cyan
Write-Host '  - Cisco Packet Tracer: unduh sendiri di https://www.netacad.com/cisco-packet-tracer (butuh login NetAcad).'
Write-Host '  - MySQL 9.7 jalan sebagai service MySQL97 di port 3306 (root tanpa password, hanya localhost).'
Write-Host '    Kalau Laragon juga menjalankan MySQL/MariaDB, ubah salah satu port-nya agar tidak bentrok.'
Write-Host '  - Fuseki: jalankan C:\tools\fuseki\fuseki-server.bat  ->  http://localhost:3030'
Write-Host '  - Android Studio: saat pertama dibuka akan mengunduh Android SDK (1 GB+).'
Read-Host 'Tekan Enter untuk menutup'
