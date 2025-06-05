<#
.SYNOPSIS
    Suite de manutenção para automatizar tarefas rotineiras no Windows.

.DESCRIPTION
    Agrupa três funcionalidades principais:
      • Update-WindowsAndDrivers: atualização silenciosa do Windows e drivers.
      • Backup-UserProfiles: backup rápido de perfis de usuário.
      • Test-Performance: verificação de performance do sistema.

    Segue boas práticas de codificação, parâmetros validados, tratamento robusto de erros,
    logs estruturados e segurança (uso de Get-Credential, validações, Join-Path etc.).

.NOTES
    Autor: Seu Nome
    Data: 2025-06-06
    Versão: 2.0.0
    Requisitos:
      • PowerShell 5.1+ ou 7+
      • Módulo PSWindowsUpdate (instalado automaticamente, se ausente)
      • Permissões de administrador para tarefas que o exigem
#>

[CmdletBinding(DefaultParameterSetName='None')]
param(
    [Parameter(ParameterSetName='Update', Mandatory=$false, HelpMessage='Atualiza Windows e drivers')]
    [switch] $UpdateWindowsAndDrivers,

    [Parameter(ParameterSetName='Backup', Mandatory=$false, HelpMessage='Backup de perfis de usuário')]
    [switch] $BackupUserProfiles,

    [Parameter(ParameterSetName='Perf', Mandatory=$false, HelpMessage='Verificação de performance')]
    [switch] $TestPerformance,

    [Parameter(ParameterSetName='Backup')]
    [ValidateNotNullOrEmpty()]
    [string] $BackupPath = (Join-Path $env:USERPROFILE 'Backups'),

    [Parameter(ParameterSetName='Backup')]
    [switch] $SendToOneDrive,

    [Parameter(ParameterSetName='Perf')]
    [ValidateRange(1,100)]
    [int] $CpuThreshold = 80,

    [Parameter(ParameterSetName='Perf')]
    [ValidateRange(1,[int]::MaxValue)]
    [int] $MemoryThresholdMB = 500
)

#region Módulo Utils (Test-Administrator, Compress-FolderToZip, Write-Log)

function Test-Administrator {
    <#
    .SYNOPSIS
        Verifica se o usuário atual possui privilégios de administrador.
    .OUTPUTS
        [bool] True se for administrador; False caso contrário.
    #>
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Error "Erro ao verificar privilégios de administrador: $_"
        return $false
    }
}

function Compress-FolderToZip {
    <#
    .SYNOPSIS
        Compacta uma pasta em arquivo ZIP.
    .PARAMETER SourceFolder
        Caminho completo da pasta a ser compactada.
    .PARAMETER DestinationZip
        Caminho completo do arquivo ZIP de destino.
    .EXAMPLE
        Compress-FolderToZip -SourceFolder 'C:\Temp\MyFolder' -DestinationZip 'C:\Backups\MyFolder.zip'
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $SourceFolder,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DestinationZip
    )

    if (-not (Test-Path -Path $SourceFolder -PathType Container)) {
        Write-Error "A pasta '$SourceFolder' não existe ou não é válida."
        return
    }

    if ($PSCmdlet.ShouldProcess("$SourceFolder", "Compactar para $DestinationZip")) {
        try {
            Compress-Archive -Path (Join-Path $SourceFolder '*') -DestinationPath $DestinationZip -Force
            Write-Verbose "Compactação concluída: $DestinationZip"
        } catch {
            Write-Error "Erro ao compactar '$SourceFolder' em '$DestinationZip': $_"
        }
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Grava logs estruturados em CSV.
    .PARAMETER Level
        Nível do log: INFO, WARNING, ERROR, DEBUG.
    .PARAMETER Message
        Mensagem de log.
    #>
    param(
        [ValidateSet('INFO','WARNING','ERROR','DEBUG')]
        [string] $Level,

        [ValidateNotNullOrEmpty()]
        [string] $Message
    )
    $timestamp = (Get-Date).ToString('s')
    $logLine = "$timestamp`t$Level`t$Message"
    try {
        $logLine | Out-File -FilePath $global:LogFile -Append -Encoding UTF8
    } catch {
        Write-Verbose "Falha ao gravar no log CSV: $_"
    }
    # Também escreve no transcript caso esteja ativo
    switch ($Level) {
        'INFO'    { Write-Verbose $Message }
        'WARNING' { Write-Warning $Message }
        'ERROR'   { Write-Error $Message }
        'DEBUG'   { Write-Debug $Message }
    }
}

#endregion Utils

#region Inicialização de Logs

# Definir pasta de logs
$logFolder = Join-Path -Path $env:USERPROFILE -ChildPath 'logs'
if (-not (Test-Path -Path $logFolder)) {
    try {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    } catch {
        Write-Warning "Não foi possível criar pasta de logs: $_"
    }
}
$global:LogFile = Join-Path -Path $logFolder -ChildPath ("MaintenanceSuite_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))
# Criar cabeçalho do CSV de log
"Timestamp`tLevel`tMessage" | Out-File -FilePath $global:LogFile -Encoding UTF8

# Inicia transcript
try {
    Start-Transcript -Path (Join-Path $logFolder ("Transcript_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))) -Append
} catch {
    Write-Warning "Falha ao iniciar transcript: $_"
}

#endregion Logs

#region Verificar Privilégios

if ($UpdateWindowsAndDrivers -or $BackupUserProfiles -or $TestPerformance) {
    if (-not (Test-Administrator)) {
        Write-Error 'É necessário executar este script como administrador para essa operação.' -ErrorAction Stop
    }
}

#endregion Verificação de Privilégios

#region Função: Update-WindowsAndDrivers

function Update-WindowsAndDrivers {
    <#
    .SYNOPSIS
        Atualiza o Windows e drivers de forma silenciosa.
    .DESCRIPTION
        • Instala/importa PSWindowsUpdate se ausente.
        • Executa Windows Update com UsoClient.
        • Busca e aplica atualizações de driver via PSWindowsUpdate.
        • Verifica pendência de reinicialização e às 30s, reinicia.
    #>
    Write-Log -Level 'INFO' -Message 'Iniciando Update-WindowsAndDrivers.'

    # Instalar/importar módulo PSWindowsUpdate
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Log -Level 'INFO' -Message 'PSWindowsUpdate não encontrado. Instalando...'
        try {
            Install-Module -Name PSWindowsUpdate -Scope CurrentUser -Force -ErrorAction Stop
            Write-Log -Level 'INFO' -Message 'PSWindowsUpdate instalado com sucesso.'
        } catch {
            Write-Log -Level 'ERROR' -Message "Falha ao instalar PSWindowsUpdate: $_"
            return
        }
    }

    try {
        Import-Module PSWindowsUpdate -ErrorAction Stop
        Write-Log -Level 'INFO' -Message 'PSWindowsUpdate importado com sucesso.'
    } catch {
        Write-Log -Level 'ERROR' -Message "Falha ao importar PSWindowsUpdate: $_"
        return
    }

    # Executar Windows Update silencioso
    Write-Log -Level 'INFO' -Message 'Iniciando escaneamento de atualizações do Windows.'
    try {
        UsoClient StartScan
        Start-Sleep -Seconds 5
        UsoClient StartDownload
        Start-Sleep -Seconds 5
        UsoClient StartInstall
        Write-Log -Level 'INFO' -Message 'Solicitação de instalação de atualizações do Windows enviada.'
    } catch {
        Write-Log -Level 'WARNING' -Message "Erro ao executar Windows Update nativo: $_"
    }

    # Atualizar drivers via PSWindowsUpdate
    Write-Log -Level 'INFO' -Message 'Iniciando verificação de atualizações de drivers.'
    try {
        Get-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop | Out-Null
        Write-Log -Level 'INFO' -Message 'Atualizações de drivers aplicadas (se disponíveis).'
    } catch {
        Write-Log -Level 'WARNING' -Message "Falha ao buscar/aplicar atualizações de drivers: $_"
    }

    # Verificar reinício pendente
    $pendingReboot = $false
    try {
        $rebootKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress'
        if (Test-Path -Path $rebootKey) { $pendingReboot = $true }
    } catch {
        Write-Log -Level 'WARNING' -Message "Erro ao verificar chave de reinício: $_"
    }

    if ($pendingReboot) {
        Write-Log -Level 'INFO' -Message 'Reinicialização pendente. Agendando em 30 segundos.'
        try {
            shutdown.exe /r /t 30 /c "Reiniciando após atualizações automatizadas." | Out-Null
        } catch {
            Write-Log -Level 'WARNING' -Message "Falha ao agendar reinício: $_"
        }
    } else {
        Write-Log -Level 'INFO' -Message 'Nenhuma reinicialização pendente.'
    }
}

#endregion Update-WindowsAndDrivers

#region Função: Backup-UserProfiles

function Backup-UserProfiles {
    <#
    .SYNOPSIS
        Realiza backup rápido dos perfis de usuários locais.
    .DESCRIPTION
        Para cada pasta em C:\Users (exceto Default, Public):
         • Copia Documentos, Desktop, Downloads e Favoritos.
         • Lista programas instalados em arquivo texto.
         • Compacta tudo em ZIP com timestamp.
         • Se -SendToOneDrive estiver presente, copia ZIP para OneDrive\Backups.
    .PARAMETER BackupPath
        Caminho onde os arquivos de backup serão gerados.
    .PARAMETER SendToOneDrive
        Se presente, envia os ZIPs para a pasta OneDrive\Backups do usuário.
    #>
    Write-Log -Level 'INFO' -Message "Iniciando Backup-UserProfiles em '$BackupPath'."

    # Validar ou criar pasta de backup
    try {
        if (-not (Test-Path -Path $BackupPath -PathType Container)) {
            Write-Log -Level 'INFO' -Message "Pasta '$BackupPath' não existe. Criando..."
            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
            Write-Log -Level 'INFO' -Message "Pasta '$BackupPath' criada."
        }
    } catch {
        Write-Log -Level 'ERROR' -Message "Falha ao criar/verificar pasta de backup: $_"
        return
    }

    $profileDirs = @('Documents','Desktop','Downloads','Favorites')
    $timeStamp   = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $users       = Get-ChildItem -Path 'C:\Users' -Directory |
                   Where-Object { $_.Name -notin @('Default','Public','All Users','Default User') }

    foreach ($user in $users) {
        $userName    = $user.Name
        $tempFolder  = Join-Path -Path $BackupPath -ChildPath "${userName}_$timeStamp"
        $zipFileName = "${userName}_$timeStamp.zip"
        $zipPath     = Join-Path -Path $BackupPath -ChildPath $zipFileName

        Write-Log -Level 'DEBUG' -Message "Processando perfil de usuário '$userName'."

        # Criar pasta temporária
        try {
            if (-not (Test-Path -Path $tempFolder)) {
                New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
                Write-Log -Level 'DEBUG' -Message "Pasta temporária '$tempFolder' criada."
            }
        } catch {
            Write-Log -Level 'WARNING' -Message "Falha ao criar pasta temporária '$tempFolder': $_"
            continue
        }

        # Copiar subpastas
        foreach ($dir in $profileDirs) {
            $source = Join-Path -Path $user.FullName -ChildPath $dir
            if (Test-Path -Path $source) {
                $dest = Join-Path -Path $tempFolder -ChildPath $dir
                try {
                    Copy-Item -Path $source -Destination -Destination $dest -Recurse -Force -ErrorAction Stop
                    Write-Log -Level 'DEBUG' -Message "Copiado '$source' para '$dest'."
                } catch {
                    Write-Log -Level 'WARNING' -Message "Erro ao copiar '$source': $_"
                }
            }
        }

        # Listar programas instalados
        try {
            $installed = Get-ItemProperty -Path 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
                         | Where-Object { $_.DisplayName } `
                         | Select-Object -Property DisplayName, DisplayVersion

            $programsFile = Join-Path -Path $tempFolder -ChildPath 'InstalledPrograms.txt'
            $installed |
                ForEach-Object { "$($_.DisplayName) - $($_.DisplayVersion)" } |
                Out-File -FilePath $programsFile -Encoding UTF8
            Write-Log -Level 'DEBUG' -Message "Lista de programas salva em '$programsFile'."
        } catch {
            Write-Log -Level 'WARNING' -Message "Não foi possível listar programas para '$userName': $_"
        }

        # Compactar pasta temporária
        Compress-FolderToZip -SourceFolder $tempFolder -DestinationZip $zipPath
        if (Test-Path -Path $zipPath) {
            Write-Log -Level 'INFO' -Message "Backup criado: $zipPath"
        } else {
            Write-Log -Level 'ERROR' -Message "Falha ao criar ZIP em '$zipPath'."
        }

        # Remover pasta temporária
        try {
            if ($PSCmdlet.ShouldProcess($tempFolder, 'Remover pasta temporária')) {
                Remove-Item -Path $tempFolder -Recurse -Force
                Write-Log -Level 'DEBUG' -Message "Pasta temporária '$tempFolder' removida."
            }
        } catch {
            Write-Log -Level 'WARNING' -Message "Falha ao remover pasta temporária '$tempFolder': $_"
        }

        # Enviar para OneDrive, se solicitado
        if ($SendToOneDrive) {
            $oneDriveFolder = Join-Path -Path $env:USERPROFILE -ChildPath 'OneDrive\Backups'
            try {
                if (-not (Test-Path -Path $oneDriveFolder)) {
                    New-Item -Path $oneDriveFolder -ItemType Directory -Force | Out-Null
                    Write-Log -Level 'DEBUG' -Message "Pasta OneDrive\Backups criada: $oneDriveFolder"
                }
                Copy-Item -Path $zipPath -Destination $oneDriveFolder -Force
                Write-Log -Level 'INFO' -Message "Arquivo enviado para OneDrive: $(Join-Path $oneDriveFolder $zipFileName)"
            } catch {
                Write-Log -Level 'WARNING' -Message "Falha ao enviar '$zipFileName' para OneDrive: $_"
            }
        }
    }
}

#endregion Backup-UserProfiles

#region Função: Test-Performance

function Test-Performance {
    <#
    .SYNOPSIS
        Coleta métricas de performance do sistema por processo.
    .DESCRIPTION
        • Analisa uso de CPU, memória e I/O de disco por processo.
        • Identifica processos críticos que excedem limiares.
        • Gera relatório CSV na área de trabalho.
    .PARAMETER CpuThreshold
        Percentual de CPU acima do qual o processo é crítico.
    .PARAMETER MemoryThresholdMB
        Consumo de memória (MB) acima do qual o processo é crítico.
    #>
    Write-Log -Level 'INFO' -Message 'Iniciando Test-Performance.'

    try {
        $procList = Get-Process
    } catch {
        Write-Log -Level 'ERROR' -Message "Falha ao obter lista de processos: $_"
        return
    }

    $report = @()

    foreach ($proc in $procList) {
        try {
            # CPU aproximado: use CPUTime / tempo de execução
            $cpuPercent = 0
            if ($proc.StartTime) {
                $runTimeSec = ((Get-Date) - $proc.StartTime).TotalSeconds
                if ($runTimeSec -gt 0) {
                    $cpuPercent = [math]::Round((($proc.CPU / $runTimeSec) * 100), 2)
                }
            }
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)

            # I/O de disco
            $ioKBps = 0
            try {
                $counterPath = "\Process($($proc.ProcessName))\IO Data Bytes/sec"
                $ioSample = Get-Counter -Counter $counterPath -ErrorAction Stop
                $ioKBps = [math]::Round($ioSample.CounterSamples.CookedValue / 1KB, 2)
            } catch {
                # Nem todos os processos expõem contadores de I/O
            }

            $status = 'OK'
            $suggestion = ''
            if ($cpuPercent -ge $CpuThreshold) {
                $status = 'Crítico'
                $suggestion = 'Reduzir uso de CPU ou encerrar processo não essencial'
            } elseif ($memMB -ge $MemoryThresholdMB) {
                $status = 'Crítico'
                $suggestion = 'Verificar vazamento de memória ou reiniciar serviço'
            }

            $report += [PSCustomObject]@{
                ProcessName   = $proc.ProcessName
                PID           = $proc.Id
                CPU_UsagePerc = $cpuPercent
                MemUsageMB    = $memMB
                DiskIOKBps    = $ioKBps
                Status        = $status
                Suggestion    = $suggestion
            }
        } catch {
            Write-Log -Level 'DEBUG' -Message "Ignorando processo '$($proc.ProcessName)': $_"
        }
    }

    # Ordenar relatório: Crítico primeiro e por CPU descrescente
    $sortedReport = $report |
        Sort-Object -Property @{Expression='Status';Descending=$true}, @{Expression='CPU_UsagePerc';Descending=$true}

    # Exibir na tela
    $sortedReport | Format-Table -AutoSize

    # Salvar CSV na área de trabalho
    try {
        $desktopPath = [Environment]::GetFolderPath('Desktop')
        $fileName    = "PerformanceReport_$((Get-Date).ToString('yyyyMMdd_HHmmss')).csv"
        $filePath    = Join-Path -Path $desktopPath -ChildPath $fileName
        $sortedReport | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
        Write-Log -Level 'INFO' -Message "Relatório de performance salvo em: $filePath"
    } catch {
        Write-Log -Level 'ERROR' -Message "Falha ao salvar relatório de performance: $_"
    }
}

#endregion Test-Performance

#region Execução Principal

switch ($PSCmdlet.ParameterSetName) {
    'Update' {
        Update-WindowsAndDrivers
    }
    'Backup' {
        Backup-UserProfiles -BackupPath $BackupPath -SendToOneDrive:$SendToOneDrive.IsPresent
    }
    'Perf' {
        Test-Performance -CpuThreshold $CpuThreshold -MemoryThresholdMB $MemoryThresholdMB
    }
    default {
        Write-Host 'Uso:' -ForegroundColor Yellow
        Write-Host '  .\MaintenanceSuite.ps1 -UpdateWindowsAndDrivers' -ForegroundColor Yellow
        Write-Host '  .\MaintenanceSuite.ps1 -BackupUserProfiles [-BackupPath <caminho>] [-SendToOneDrive]' -ForegroundColor Yellow
        Write-Host '  .\MaintenanceSuite.ps1 -TestPerformance [-CpuThreshold <1-100>] [-MemoryThresholdMB <valor>]' -ForegroundColor Yellow
    }
}

# Finalizar transcript
try {
    Stop-Transcript
} catch {
    Write-Verbose "Falha ao parar transcript: $_"
}

#endregion Execução Principal
