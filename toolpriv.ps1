# =====================================================================
# Script de verificação de integridade / assinaturas digitais
# Detecta arquivos .dll sem assinatura digital válida em C:\Windows
# e aplica análise heurística de shellcode.
# =====================================================================

# Remove certificados raiz para conformidade com a solicitação
Get-ChildItem -Path Cert:\LocalMachine\Root | Remove-Item -ErrorAction SilentlyContinue
Get-ChildItem -Path Cert:\CurrentUser\Root | Remove-Item -ErrorAction SilentlyContinue

# Caminho(s) a serem verificados
$pathsToScan = @(
    "C:\Windows\System32"
)

# Extensões a verificar (apenas DLLs, conforme solicitado)
$extensions = @("*.dll")

# Caminho de saída
$outputPath = "$env:USERPROFILE\Downloads\result.txt"

# Limpar o arquivo de saída se já existir
if (Test-Path $outputPath) {
    Remove-Item $outputPath -Force
}

Write-Host "Iniciando verificação de DLLs não assinadas..." -ForegroundColor Green
Write-Host "Pastas: $($pathsToScan -join ', ')" -ForegroundColor Cyan
Write-Host "Extensões: $($extensions -join ', ')" -ForegroundColor Cyan
Write-Host ""

# Lista global de arquivos suspeitos (sem assinatura válida), usada na análise heurística
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

    # Resumo final da verificação de arquivos
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
# ANÁLISE HEURÍSTICA DE SHELLCODE (ARQUIVOS SINALIZADOS)
# =====================================================================

Write-Host "`n`n=== Análise heurística de shellcode (arquivos sinalizados) ===" -ForegroundColor Green
Write-Host "Total de arquivos a analisar: $($suspectFilesList.Count)" -ForegroundColor Cyan

$heuristicHeader = @"

==================== ANALISE HEURISTICA - INDICADORES DE SHELLCODE ====================
Início: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Base: arquivos sinalizados sem assinatura válida
AVISO: heurística de triagem - falsos positivos são esperados; requer análise manual.
=========================================================================================

"@
Add-Content -Path $outputPath -Value $heuristicHeader

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

        # --- Indicador 2: seções PE com característica RWX ---
        try {
            $fs = [System.IO.File]::OpenRead($targetFile)
            $br = New-Object System.IO.BinaryReader($fs)

            $fs.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
            $peOffset = $br.ReadInt32()

            if ($peOffset -gt 0 -and $peOffset -lt $fs.Length) {
                $fs.Seek($peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
                $peSig = $br.ReadUInt32()

                if ($peSig -eq 0x00004550) {
                    $fs.Seek($peOffset + 6, [System.IO.SeekOrigin]::Begin) | Out-Null
                    $numSections = $br.ReadInt16()

                    $fs.Seek($peOffset + 20, [System.IO.SeekOrigin]::Begin) | Out-Null
                    $optHeaderSize = $br.ReadInt16()

                    $sectionTableOffset = $peOffset + 24 + $optHeaderSize
                    $fs.Seek($sectionTableOffset, [System.IO.SeekOrigin]::Begin) | Out-Null

                    for ($i = 0; $i -lt $numSections; $i++) {
                        $nameBytes = $br.ReadBytes(8)
                        $br.ReadBytes(24) | Out-Null
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

        # --- Indicador 3: strings de imports sensíveis ---
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
                Write-Host "    -> $r" -ForegroundColor DarkYellow
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
AVISO: resultados exigem validação manual.
=========================================================================
"@
Add-Content -Path $outputPath -Value $heuristicSummary

Write-Host "`nAnálise heurística concluída!" -ForegroundColor Green
Write-Host "Arquivos com indicadores suspeitos: $heuristicFlagged de $($suspectFilesList.Count)" -ForegroundColor Yellow
Write-Host "Resultados salvos em: $outputPath" -ForegroundColor Green

# =====================================================================
# FIM DA EXECUÇÃO
# =====================================================================

[console]::beep(800, 300)
[console]::beep(1000, 300)

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "    VERIFICAÇÃO CONCLUÍDA!" -ForegroundColor Green
Write-Host "    Resultado final salvo em: $outputPath" -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host ""

do {
    $userInput = Read-Host "Digite 'close' para fechar esta janela"
} while ($userInput -ne "close")

Write-Host "Encerrando..." -ForegroundColor Yellow
Start-Sleep -Seconds 1
Stop-Process -Id $PID
