# Inventario_Sistema_Windows_Pro_V1.ps1

param(
    [string]$ExportFormat = "CSV",
    [string]$RemoteServer = "",
    [string]$RemotePath = "",
    [string]$User = "",
    [string]$Password = ""
)

Start-Transcript -Path "$env:USERPROFILE\logs\inv_$(Get-Date -Format 'yyyyMMdd_HHmmss').log" -Append

function Get-SerialNumber {
    try {
        (Get-CimInstance -Class Win32_BIOS).SerialNumber
    } catch {
        "N/A"
    }
}

function Get-UUID {
    try {
        (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
    } catch {
        "N/A"
    }
}

function Get-Uptime {
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        ((Get-Date) - ($os.LastBootUpTime)).ToString()
    } catch {
        "N/A"
    }
}

function Get-BootHistory {
    try {
        Get-WinEvent -LogName System -FilterHashtable @{Id=6005} -MaxEvents 5 | Select-Object TimeCreated
    } catch {
        "N/A"
    }
}

function Get-DiskInfo {
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        [PSCustomObject]@{
            DeviceID = $_.DeviceID
            SizeGB = [math]::Round($_.Size / 1GB, 2)
            FreeGB = [math]::Round($_.FreeSpace / 1GB, 2)
            UsedGB = [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)
        }
    }
}

function Get-MACAddresses {
    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty MacAddress
}

function Get-IPAddresses {
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.*' } | Select-Object -ExpandProperty IPAddress
}

function Get-SystemInventory {
    $diskInfo = Get-DiskInfo | ConvertTo-Json -Depth 3
    $boots = Get-BootHistory | ForEach-Object { $_.TimeCreated } | Out-String

    [PSCustomObject]@{
        Hostname      = $env:COMPUTERNAME
        OSVersion     = (Get-CimInstance Win32_OperatingSystem).Caption
        SerialNumber  = Get-SerialNumber
        UUID          = Get-UUID
        Domain        = (Get-CimInstance Win32_ComputerSystem).Domain
        Uptime        = Get-Uptime
        LastBoots     = $boots.Trim()
        IPAddress     = (Get-IPAddresses) -join ", "
        MACAddress    = (Get-MACAddresses) -join ", "
        DiskInfo      = $diskInfo
        Timestamp     = (Get-Date -Format 'u')
    }
}

$inventory = Get-SystemInventory

switch ($ExportFormat.ToUpper()) {
    "CSV" {
        $inventory | Export-Csv -Path "$env:USERPROFILE\Desktop\system_inventory.csv" -NoTypeInformation -Encoding UTF8
    }
    "JSON" {
        $inventory | ConvertTo-Json -Depth 3 | Set-Content "$env:USERPROFILE\Desktop\system_inventory.json" -Encoding UTF8
    }
    default {
        Write-Warning "[AVISO] Formato de exportação não reconhecido: $ExportFormat"
    }
}

# Tentativa de envio remoto opcional
if ($RemoteServer -and $RemotePath) {
    try {
        $session = New-PSSession -ComputerName $RemoteServer -Credential (New-Object System.Management.Automation.PSCredential($User,(ConvertTo-SecureString $Password -AsPlainText -Force)))
        Copy-Item -Path "$env:USERPROFILE\Desktop\system_inventory.$ExportFormat" -Destination $RemotePath -ToSession $session
        Remove-PSSession $session
    } catch {
        Write-Warning "[ERRO] Falha no envio remoto: $_"
    }
}

Stop-Transcript
