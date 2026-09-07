# =====================================================================
# Script de verificação de integridade / assinaturas digitais
# Detecta arquivos .dll, .exe, .sys, .tmp sem assinatura digital válida
# em C:\Windows (pode indicar arquivos adulterados, substituídos ou
# maliciosos disfarçados de arquivos do sistema)
# =====================================================================

param(
    # Chave de API do VirusTotal (obtenha gratuitamente em virustotal.com/gui/my-apikey)
    # Passe via: .\verificar_assinaturas.ps1 -VtApiKey "SUA_CHAVE_AQUI"
    # Se não informado, tenta usar a variável de ambiente VT_API_KEY.
    # Se nenhum dos dois existir, a etapa de consulta ao VirusTotal (Parte 4) é pulada.
    [string]$VtApiKey = "ab0d1e803df4047532150acc1fecc35ce875f2dce7739c724027fb068abb67b9"
)

# Fallback: usa variável de ambiente VT_API_KEY se -VtApiKey não foi passado
if ([string]::IsNullOrWhiteSpace($VtApiKey) -and -not [string]::IsNullOrWhiteSpace($env:VT_API_KEY)) {
    $VtApiKey = $env:VT_API_KEY
}

# Caminho(s) a serem verificados - ajuste conforme necessário
$pathsToScan = @(
    "C:\Windows\System32"
)

# Extensões a verificar
$extensions = @("*.dll", "*.exe")

# Caminho de saída
$outputPath = "$env:USERPROFILE\Downloads\result.txt"

# Limpar o arquivo de saída se já existir
if (Test-Path $outputPath) {
    Remove-Item $outputPath -Force
}

Write-Host "Iniciando verificação de assinaturas digitais..." -ForegroundColor Green
Write-Host "Pastas: $($pathsToScan -join ', ')" -ForegroundColor Cyan
Write-Host "Extensões: $($extensions -join ', ')" -ForegroundColor Cyan
Write-Host "Isso pode levar bastante tempo, dependendo do volume de arquivos..." -ForegroundColor Yellow
Write-Host ""

# Lista global de arquivos suspeitos (sem assinatura válida), usada na Parte 3
# para a análise heurística de shellcode
$suspectFilesList = New-Object System.Collections.Generic.List[string]

# Contadores
$totalFiles = 0
$unsignedFiles = 0
$suspiciousFiles = 0

# Cabeçalho do relatório
$header = @"
==================== RELATORIO DE VERIFICACAO ====================
Início: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Pastas verificadas: $($pathsToScan -join ', ')
Extensões: $($extensions -join ', ')
=====================================================================

"@
Add-Content -Path $outputPath -Value $header

try {
    foreach ($basePath in $pathsToScan) {

        if (-not (Test-Path $basePath)) {
            Write-Host "Pasta não encontrada, pulando: $basePath" -ForegroundColor DarkYellow
            continue
        }

        Write-Host "`n--- Verificando: $basePath ---" -ForegroundColor Magenta

        Get-ChildItem -Path $basePath -Include $extensions -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $totalFiles++
            $file = $_.FullName

            try {
                # Verifica assinatura digital
                $signature = Get-AuthenticodeSignature -FilePath $file -ErrorAction Stop

                if ($signature.Status -ne "Valid") {
                    $unsignedFiles++

                    $status = switch ($signature.Status) {
                        "NotSigned"     { "Não assinado" }
                        "HashMismatch"  { "Hash não corresponde (POSSÍVEL ADULTERAÇÃO)" }
                        "NotTrusted"    { "Não confiável" }
                        "UnknownError"  { "Erro desconhecido" }
                        default         { $signature.Status.ToString() }
                    }

                    # HashMismatch é o sinal mais forte de que o arquivo foi alterado
                    # depois de assinado — bandeira vermelha de possível bypass/tampering
                    if ($signature.Status -eq "HashMismatch") {
                        $suspiciousFiles++
                        Write-Host "SUSPEITO (hash não bate): $file" -ForegroundColor Red -BackgroundColor Black
                    }
                    else {
                        Write-Host "Sem assinatura válida: $file - $status" -ForegroundColor Red
                    }

                    $output = "$file | Ext: $($_.Extension) | Status: $status | Assinante: $($signature.SignerCertificate.Subject) | Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                    Add-Content -Path $outputPath -Value $output
                    $suspectFilesList.Add($file)
                }
            }
            catch {
                $unsignedFiles++
                $output = "$file | Ext: $($_.Extension) | Status: ERRO_VERIFICACAO | Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                Add-Content -Path $outputPath -Value $output
                Write-Host "Erro ao verificar: $file" -ForegroundColor DarkRed
            }

            if ($totalFiles % 200 -eq 0) {
                Write-Host "Progresso: $totalFiles arquivos processados..." -ForegroundColor Cyan
            }
        }
    }

    # Resumo final
    $summary = @"

==================== RESUMO ====================
Total de arquivos verificados: $totalFiles
Arquivos sem assinatura válida: $unsignedFiles
Arquivos com HASH INCOMPATÍVEL (mais suspeitos): $suspiciousFiles
Fim: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
===============================================
"@
    Add-Content -Path $outputPath -Value $summary

    Write-Host "`nVerificação concluída!" -ForegroundColor Green
    Write-Host "Total verificado: $totalFiles" -ForegroundColor Cyan
    Write-Host "Sem assinatura válida: $unsignedFiles" -ForegroundColor Yellow
    Write-Host "Hash incompatível (mais críticos): $suspiciousFiles" -ForegroundColor Red
    Write-Host "Resultados salvos em: $outputPath" -ForegroundColor Green
}
catch {
    Write-Host "Erro durante a execução: $_" -ForegroundColor Red
}

# =====================================================================
# PARTE 2: Verificar DLLs carregadas em processos em execução
# Detecta módulos sem assinatura válida carregados em processos ativos
# (indicador de possível DLL injection). Requer PowerShell como
# Administrador - alguns processos do sistema ainda podem negar acesso.
# =====================================================================

Write-Host "`n`n=== Verificando DLLs carregadas em processos ativos ===" -ForegroundColor Green

$processHeader = @"

==================== DLLs EM PROCESSOS EM EXECUCAO ====================
Início: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
=========================================================================

"@
Add-Content -Path $outputPath -Value $processHeader

$totalModules = 0
$suspiciousModules = 0
$deniedProcesses = 0
$timeoutProcesses = 0

# Nomes de processos protegidos/sistema que costumam travar ou negar
# acesso ao ler .Modules (System, Registry, processos com PPL como
# antivírus, etc.) - pulados direto para não gastar tempo com eles.
$skipProcessNames = @("System", "Idle", "Registry", "Secure System", "Memory Compression")

# Acessa .Modules de um processo com timeout, usando um runspace isolado.
# Isso evita que o script trave para sempre caso um processo específico
# (comum em processos protegidos/PPL/AppContainer, como apps UWP) nunca
# retorne a chamada. Importante: o abort em caso de timeout é assíncrono
# (BeginStop), porque Stop() síncrono também pode travar se a chamada
# nativa dentro do runspace nunca responder.
function Get-ModulesWithTimeout {
    param(
        [int]$ProcessId,
        [int]$TimeoutSeconds = 5
    )

    $ps = [PowerShell]::Create()
    $ps.AddScript({
        param($targetPid)
        try {
            $p = Get-Process -Id $targetPid -ErrorAction Stop
            # Força a materialização da coleção agora, dentro do runspace,
            # para que o timeout realmente cubra a parte lenta/travável.
            return @($p.Modules)
        }
        catch {
            return $null
        }
    }) | Out-Null
    $ps.AddArgument($ProcessId) | Out-Null

    $asyncResult = $ps.BeginInvoke()
    $completed = $asyncResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))

    if ($completed) {
        try {
            $result = $ps.EndInvoke($asyncResult)
        }
        catch {
            $result = $null
        }
        $ps.Dispose()
        return @{ Success = $true; Modules = $result }
    }
    else {
        # Travou: aborta de forma ASSÍNCRONA (não espera o abort terminar,
        # já que a chamada nativa presa pode nunca responder ao Stop()).
        # O runspace/objeto fica pendente de limpeza pelo garbage collector,
        # o que é aceitável num script de execução única como este.
        try { $ps.BeginStop({}, $null) | Out-Null } catch {}
        return @{ Success = $false; Modules = $null }
    }
}

$allProcesses = Get-Process -ErrorAction SilentlyContinue
$totalProcessesToCheck = $allProcesses.Count
Write-Host "Total de processos a verificar: $totalProcessesToCheck" -ForegroundColor Cyan

# Prazo total para a Parte 2 inteira. Mesmo com o timeout por processo,
# em máquinas com muitos processos/DLLs isso pode somar bastante tempo -
# passado esse prazo, os processos restantes ficam como não analisados.
$processDeadline = (Get-Date).AddMinutes(10)
$processIndex = 0
$processesNotAnalyzed = 0

foreach ($proc in $allProcesses) {

    $processIndex++

    if ((Get-Date) -ge $processDeadline) {
        $processesNotAnalyzed += ($totalProcessesToCheck - $processIndex + 1)
        Write-Host "Prazo de 10 min para verificação de processos esgotado. $processesNotAnalyzed processos restantes marcados como NAO_ANALISADO." -ForegroundColor DarkGray
        $output = "PROCESSOS RESTANTES | FLAG: NAO_ANALISADO | Motivo: prazo de 10 min para verificação de processos esgotado | Quantidade: $processesNotAnalyzed | Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Add-Content -Path $outputPath -Value $output
        break
    }

    # Heartbeat de progresso a cada processo, para deixar claro que o
    # script está ativo mesmo quando não há DLL suspeita para mostrar
    Write-Host "[$processIndex/$totalProcessesToCheck] Verificando: $($proc.ProcessName) (PID $($proc.Id))..." -ForegroundColor DarkCyan

    if ($skipProcessNames -contains $proc.ProcessName) {
        $deniedProcesses++
        continue
    }

    $moduleResult = Get-ModulesWithTimeout -ProcessId $proc.Id -TimeoutSeconds 5

    if (-not $moduleResult.Success) {
        $timeoutProcesses++
        Write-Host "Timeout ao ler módulos de PID $($proc.Id) ($($proc.ProcessName)) - pulando" -ForegroundColor DarkGray
        continue
    }

    $modules = $moduleResult.Modules
    if ($null -eq $modules) {
        $deniedProcesses++
        continue
    }

    foreach ($mod in $modules) {
        $totalModules++
        $modPath = $mod.FileName

        if ([string]::IsNullOrEmpty($modPath) -or -not (Test-Path $modPath)) {
            continue
        }

        try {
            $sig = Get-AuthenticodeSignature -FilePath $modPath -ErrorAction Stop

            if ($sig.Status -ne "Valid") {
                $suspiciousModules++

                $status = switch ($sig.Status) {
                    "NotSigned"    { "Não assinado" }
                    "HashMismatch" { "Hash não corresponde (POSSÍVEL ADULTERAÇÃO)" }
                    "NotTrusted"   { "Não confiável" }
                    "UnknownError" { "Erro desconhecido" }
                    default        { $sig.Status.ToString() }
                }

                Write-Host "DLL suspeita | PID $($proc.Id) ($($proc.ProcessName)) -> $modPath | $status" -ForegroundColor Red

                $output = "PID: $($proc.Id) | Processo: $($proc.ProcessName) | DLL: $modPath | Status: $status | Assinante: $($sig.SignerCertificate.Subject) | Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                Add-Content -Path $outputPath -Value $output
                if (-not $suspectFilesList.Contains($modPath)) {
                    $suspectFilesList.Add($modPath)
                }
            }
        }
        catch {
            # Não conseguiu verificar (arquivo bloqueado, etc.)
            continue
        }
    }
}

$processSummary = @"

==================== RESUMO - PROCESSOS ====================
Total de módulos (DLLs) verificados: $totalModules
Módulos sem assinatura válida: $suspiciousModules
Processos com acesso negado (não verificados): $deniedProcesses
Processos com timeout (pulados após 5s): $timeoutProcesses
Processos não analisados (prazo de 10 min esgotado): $processesNotAnalyzed
Fim: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
===============================================================
"@
Add-Content -Path $outputPath -Value $processSummary

Write-Host "`nVerificação de processos concluída!" -ForegroundColor Green
Write-Host "Módulos verificados: $totalModules" -ForegroundColor Cyan
Write-Host "Módulos sem assinatura válida: $suspiciousModules" -ForegroundColor Yellow
Write-Host "Processos com acesso negado: $deniedProcesses" -ForegroundColor DarkYellow
Write-Host "Processos com timeout: $timeoutProcesses" -ForegroundColor DarkGray
Write-Host "Processos não analisados (prazo esgotado): $processesNotAnalyzed" -ForegroundColor DarkGray
Write-Host "Resultados salvos em: $outputPath" -ForegroundColor Green

# =====================================================================
# PARTE 3: Análise heurística de shellcode nos arquivos já sinalizados
# IMPORTANTE: isto é TRIAGEM, não detecção definitiva. Mede sinais que
# shellcode/payloads costumam apresentar (alta entropia = dados
# compactados/criptografados, e seções de código com permissão de
# escrita). Falsos positivos existem (ex: instaladores, packers
# legítimos como UPX, .NET ofuscado). Use como indicativo para
# investigação manual, não como veredito automático.
# =====================================================================

Write-Host "`n`n=== Análise heurística de shellcode (arquivos sinalizados) ===" -ForegroundColor Green
Write-Host "Total de arquivos a analisar: $($suspectFilesList.Count)" -ForegroundColor Cyan

$heuristicHeader = @"

==================== ANALISE HEURISTICA - INDICADORES DE SHELLCODE ====================
Início: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Base: arquivos sinalizados sem assinatura válida nas Partes 1 e 2
AVISO: heurística de triagem - falsos positivos são esperados; requer análise manual.
=========================================================================================

"@
Add-Content -Path $outputPath -Value $heuristicHeader

# Calcula entropia de Shannon (0 a 8) de um bloco de bytes.
# Valores altos (>7.2) tipicamente indicam dados compactados ou criptografados.
function Get-ShannonEntropy {
    param([byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return 0 }

    $freq = New-Object 'int[]' 256
    foreach ($b in $Bytes) { $freq[$b]++ }

    $len = $Bytes.Length
    $entropy = 0.0
    foreach ($count in $freq) {
        if ($count -gt 0) {
            $p = $count / $len
            $entropy -= $p * [Math]::Log($p, 2)
        }
    }
    return [Math]::Round($entropy, 3)
}

$heuristicFlagged = 0

foreach ($targetFile in $suspectFilesList) {

    if (-not (Test-Path $targetFile)) { continue }

    try {
        $reasons = New-Object System.Collections.Generic.List[string]

        # --- Indicador 1: entropia geral do arquivo ---
        $bytes = [System.IO.File]::ReadAllBytes($targetFile)
        $entropy = Get-ShannonEntropy -Bytes $bytes
        if ($entropy -ge 7.2) {
            $reasons.Add("Entropia alta ($entropy) - possível compactação/criptografia de payload")
        }

        # --- Indicador 2: seções PE com característica RWX (Read+Write+Execute) ---
        # Seções legítimas raramente precisam ser graváveis E executáveis ao mesmo tempo.
        # IMAGE_SCN_MEM_EXECUTE = 0x20000000, IMAGE_SCN_MEM_WRITE = 0x80000000
        try {
            $fs = [System.IO.File]::OpenRead($targetFile)
            $br = New-Object System.IO.BinaryReader($fs)

            $fs.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
            $peOffset = $br.ReadInt32()

            if ($peOffset -gt 0 -and $peOffset -lt $fs.Length) {
                $fs.Seek($peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
                $peSig = $br.ReadUInt32()  # deve ser 0x00004550 ("PE\0\0")

                if ($peSig -eq 0x00004550) {
                    $fs.Seek($peOffset + 6, [System.IO.SeekOrigin]::Begin) | Out-Null
                    $numSections = $br.ReadInt16()

                    $fs.Seek($peOffset + 20, [System.IO.SeekOrigin]::Begin) | Out-Null
                    $optHeaderSize = $br.ReadInt16()

                    $sectionTableOffset = $peOffset + 24 + $optHeaderSize
                    $fs.Seek($sectionTableOffset, [System.IO.SeekOrigin]::Begin) | Out-Null

                    for ($i = 0; $i -lt $numSections; $i++) {
                        $nameBytes = $br.ReadBytes(8)
                        $br.ReadBytes(24) | Out-Null  # campos intermediários não usados aqui
                        $characteristics = $br.ReadUInt32()

                        $isExecutable = ($characteristics -band 0x20000000) -ne 0
                        $isWritable   = ($characteristics -band 0x80000000) -ne 0

                        if ($isExecutable -and $isWritable) {
                            $secName = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
                            $reasons.Add("Seção RWX detectada: '$secName' (gravável + executável)")
                        }
                    }
                }
            }
            $br.Close()
            $fs.Close()
        }
        catch {
            if ($fs) { $fs.Close() }
        }

        # --- Indicador 3: strings de imports sensíveis embutidas no binário ---
        # Presença combinada dessas funções é comum em técnicas de injeção/execução de shellcode
        $suspiciousApis = @("VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "RtlMoveMemory", "LoadLibraryA", "GetProcAddress")
        $asciiContent = [System.Text.Encoding]::ASCII.GetString($bytes)
        $foundApis = $suspiciousApis | Where-Object { $asciiContent -like "*$_*" }
        if ($foundApis.Count -ge 3) {
            $reasons.Add("Combinação de APIs sensíveis encontrada: $($foundApis -join ', ')")
        }

        if ($reasons.Count -gt 0) {
            $heuristicFlagged++
            Write-Host "POSSÍVEL SHELLCODE: $targetFile" -ForegroundColor Red -BackgroundColor Black
            foreach ($r in $reasons) {
                Write-Host "   -> $r" -ForegroundColor DarkYellow
            }

            $output = "$targetFile | Entropia: $entropy | Motivos: $($reasons -join ' ;; ') | Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            Add-Content -Path $outputPath -Value $output
        }
    }
    catch {
        Write-Host "Erro ao analisar $targetFile : $_" -ForegroundColor DarkRed
    }
}

$heuristicSummary = @"

==================== RESUMO - ANALISE HEURISTICA ====================
Arquivos analisados: $($suspectFilesList.Count)
Arquivos com indicadores de shellcode: $heuristicFlagged
Fim: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
AVISO: resultados exigem validação manual (ex: submissão a sandbox/VirusTotal).
=========================================================================
"@
Add-Content -Path $outputPath -Value $heuristicSummary

Write-Host "`nAnálise heurística concluída!" -ForegroundColor Green
Write-Host "Arquivos com indicadores suspeitos: $heuristicFlagged de $($suspectFilesList.Count)" -ForegroundColor Yellow
Write-Host "Resultados salvos em: $outputPath" -ForegroundColor Green

# =====================================================================
# PARTE 4: Consulta ao VirusTotal (API pública v3)
# Calcula o SHA256 de cada arquivo suspeito e consulta o VT pelo hash
# (não faz upload do arquivo - só verifica se esse hash já é conhecido
# na base do VT). Retorna uma flag: LIMPO, SUSPEITO/MALICIOSO, ou
# NAO_ENCONTRADO (hash nunca visto pelo VT antes).
#
# Requer uma API key gratuita: https://www.virustotal.com/gui/my-apikey
# A conta gratuita tem limite de ~4 requisições/minuto - o script
# respeita isso automaticamente com uma pausa entre chamadas.
# =====================================================================

if ([string]::IsNullOrWhiteSpace($VtApiKey)) {
    Write-Host "`n`n=== VirusTotal: pulado (nenhuma -VtApiKey informada) ===" -ForegroundColor DarkYellow
    Write-Host "Para habilitar, rode novamente com: .\verificar_assinaturas.ps1 -VtApiKey 'SUA_CHAVE'" -ForegroundColor DarkYellow
}
else {
    Write-Host "`n`n=== Consultando VirusTotal para arquivos suspeitos ===" -ForegroundColor Green
    Write-Host "Total de arquivos a consultar: $($suspectFilesList.Count)" -ForegroundColor Cyan
    Write-Host "Respeitando limite de ~4 req/min - prazo máximo de 15 min para esta etapa." -ForegroundColor Yellow
    Write-Host "O que não for analisado até lá recebe a flag NAO_ANALISADO." -ForegroundColor Yellow

    $vtHeader = @"

==================== RESULTADOS - VIRUSTOTAL ====================
Início: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Consulta por hash (SHA256) - não envia o arquivo, só verifica se já é conhecido
====================================================================

"@
    Add-Content -Path $outputPath -Value $vtHeader

    $vtClean = 0
    $vtMalicious = 0
    $vtNotFound = 0
    $vtErrors = 0
    $vtNotAnalyzed = 0
    $requestCount = 0

    # Prazo total para tentar analisar TODOS os arquivos, mesmo enfrentando
    # limites de taxa (429). Passado esse tempo, o que não foi analisado
    # recebe a flag NAO_ANALISADO e o script segue em frente.
    $vtDeadline = (Get-Date).AddMinutes(15)

    foreach ($targetFile in $suspectFilesList) {

        if (-not (Test-Path $targetFile)) { continue }

        # Se o prazo de 15 minutos já estourou, marca o restante como
        # não analisado sem tentar mais chamadas
        if ((Get-Date) -ge $vtDeadline) {
            $vtNotAnalyzed++
            Write-Host "[NAO_ANALISADO] $targetFile -> prazo de 15 min esgotado" -ForegroundColor DarkGray
            $output = "$targetFile | FLAG: NAO_ANALISADO | Motivo: prazo de 15 min para consulta ao VirusTotal esgotado | Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            Add-Content -Path $outputPath -Value $output
            continue
        }

        try {
            # Throttle: conta gratuita do VT permite ~4 req/min
            if ($requestCount -gt 0 -and ($requestCount % 4 -eq 0)) {
                Write-Host "Aguardando limite de taxa da API (60s)..." -ForegroundColor DarkCyan
                Start-Sleep -Seconds 60
            }

            $sha256 = (Get-FileHash -Path $targetFile -Algorithm SHA256).Hash.ToLower()
            $requestCount++

            $vtUri = "https://www.virustotal.com/api/v3/files/$sha256"
            $headers = @{ "x-apikey" = $VtApiKey }

            # Continua tentando este arquivo (esperando entre tentativas em
            # caso de 429) até conseguir resposta ou o prazo geral de 15 min
            # estourar - o que vier primeiro.
            $handled = $false

            while (-not $handled) {

                if ((Get-Date) -ge $vtDeadline) {
                    $vtNotAnalyzed++
                    Write-Host "[NAO_ANALISADO] $targetFile -> prazo de 15 min esgotado" -ForegroundColor DarkGray
                    $output = "$targetFile | FLAG: NAO_ANALISADO | Motivo: prazo de 15 min para consulta ao VirusTotal esgotado | Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                    Add-Content -Path $outputPath -Value $output
                    $handled = $true
                    break
                }

                try {
                    $response = Invoke-RestMethod -Uri $vtUri -Headers $headers -Method Get -ErrorAction Stop

                    $stats = $response.data.attributes.last_analysis_stats
                    $malicious = $stats.malicious
                    $suspicious = $stats.suspicious
                    $totalEngines = $malicious + $suspicious + $stats.undetected + $stats.harmless
                    $totalDetections = $malicious + $suspicious
                    $vtRatio = "$totalDetections/$totalEngines virus total"

                    if ($totalDetections -eq 0) {
                        $vtClean++
                        $flag = "LIMPO"
                        $color = "Green"
                    }
                    else {
                        $vtMalicious++
                        $flag = "MALICIOSO/SUSPEITO"
                        $color = "Red"
                    }

                    $popularNames = ($response.data.attributes.popular_threat_classification.suggested_threat_label)

                    Write-Host "[$flag] $targetFile -> ($vtRatio)" -ForegroundColor $color

                    $output = "$targetFile | SHA256: $sha256 | FLAG: $flag | ($vtRatio) | Classificação: $popularNames | Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                    Add-Content -Path $outputPath -Value $output
                    $handled = $true
                }
                catch {
                    $statusCode = $_.Exception.Response.StatusCode.value__

                    if ($statusCode -eq 404) {
                        $vtNotFound++
                        Write-Host "[NAO_ENCONTRADO] $targetFile -> hash desconhecido pelo VirusTotal" -ForegroundColor DarkYellow
                        $output = "$targetFile | SHA256: $sha256 | FLAG: NAO_ENCONTRADO | Hash nunca visto pelo VirusTotal | Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                        Add-Content -Path $outputPath -Value $output
                        $handled = $true
                    }
                    elseif ($statusCode -eq 429 -or $statusCode -eq 403) {
                        # Limite de taxa ou cota esgotada: espera 60s e tenta
                        # de novo, respeitando o prazo geral de 15 min.
                        $remaining = [Math]::Max(0, [Math]::Round(($vtDeadline - (Get-Date)).TotalSeconds))
                        if ($remaining -le 0) {
                            continue  # o check do topo do while vai marcar como NAO_ANALISADO
                        }
                        $waitTime = [Math]::Min(60, $remaining)
                        Write-Host "Limite de taxa/cota atingido para $targetFile, aguardando $waitTime s (prazo restante: $remaining s)..." -ForegroundColor DarkRed
                        Start-Sleep -Seconds $waitTime
                    }
                    else {
                        $vtErrors++
                        Write-Host "Erro ao consultar VT para $targetFile : $_" -ForegroundColor DarkRed
                        $output = "$targetFile | SHA256: $sha256 | FLAG: ERRO_CONSULTA | Erro: $_ | Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                        Add-Content -Path $outputPath -Value $output
                        $handled = $true
                    }
                }
            }
        }
        catch {
            $vtErrors++
            Write-Host "Erro ao processar $targetFile : $_" -ForegroundColor DarkRed
        }
    }

    $vtSummary = @"

==================== RESUMO - VIRUSTOTAL ====================
Total consultado: $($suspectFilesList.Count)
Limpos: $vtClean
Maliciosos/Suspeitos: $vtMalicious
Não encontrados na base VT: $vtNotFound
Não analisados (prazo de 15 min esgotado): $vtNotAnalyzed
Erros de consulta: $vtErrors
Fim: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
================================================================
"@
    Add-Content -Path $outputPath -Value $vtSummary

    Write-Host "`nConsulta ao VirusTotal concluída!" -ForegroundColor Green
    Write-Host "Limpos: $vtClean | Maliciosos/Suspeitos: $vtMalicious | Não encontrados: $vtNotFound | Não analisados: $vtNotAnalyzed | Erros: $vtErrors" -ForegroundColor Cyan
    Write-Host "Resultados salvos em: $outputPath" -ForegroundColor Green
}

# =====================================================================
# FIM DA EXECUÇÃO
# Avisa que tudo terminou e aguarda o usuário digitar "close" para
# encerrar a janela do PowerShell.
# =====================================================================

[console]::beep(800, 300)
[console]::beep(1000, 300)

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "   VERIFICAÇÃO COMPLETA! Todas as etapas foram concluídas." -ForegroundColor Green
Write-Host "   Resultado final salvo em: $outputPath" -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host ""

do {
    $userInput = Read-Host "Digite 'close' para fechar esta janela"
} while ($userInput -ne "close")

Write-Host "Encerrando..." -ForegroundColor Yellow
Start-Sleep -Seconds 1
Stop-Process -Id $PID
