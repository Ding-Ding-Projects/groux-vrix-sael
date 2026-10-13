[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$In,
  [Parameter(Mandatory=$true)][string]$Out,
  [Parameter(Mandatory=$true)][string]$ProjectId,
  [Parameter(Mandatory=$true)][string]$Revision,
  [string]$K = $env:BUILD_BUNDLE_KEY
)

$ErrorActionPreference = 'Stop'
$magicText = 'EPBUNDLE2'
$contextText = 'EPBCTX02'
$maxPlaintextBytes = [int64]268435456
$magicBytes = [Text.Encoding]::ASCII.GetByteCount($magicText)
$maxEnvelopeBytes = [int64]($magicBytes + 16 + 16 + 32 + $maxPlaintextBytes + 16)

if ([string]::IsNullOrWhiteSpace($K)) { throw 'Missing BUILD_BUNDLE_KEY.' }
if ($ProjectId -cnotmatch '^p[0-9a-f]{32}$') { throw 'Invalid project context.' }
if ($Revision -cnotmatch '^[0-9a-f]{32}$') { throw 'Invalid revision context.' }
if (-not (Test-Path -LiteralPath $In -PathType Leaf)) { throw 'Input not found.' }

function ConvertTo-UInt32BigEndian([uint32]$Value) {
  [byte[]]$bytes = [BitConverter]::GetBytes($Value)
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
  return ,$bytes
}

function New-ContextBytes([string]$Id, [string]$Rev) {
  [byte[]]$contextMagic = [Text.Encoding]::ASCII.GetBytes($contextText)
  [byte[]]$projectBytes = [Text.Encoding]::UTF8.GetBytes($Id)
  [byte[]]$revisionBytes = [Text.Encoding]::UTF8.GetBytes($Rev)
  [byte[]]$projectLength = ConvertTo-UInt32BigEndian ([uint32]$projectBytes.Length)
  [byte[]]$revisionLength = ConvertTo-UInt32BigEndian ([uint32]$revisionBytes.Length)
  $stream = New-Object IO.MemoryStream
  try {
    foreach ($part in @($contextMagic, $projectLength, $projectBytes, $revisionLength, $revisionBytes)) {
      $stream.Write($part, 0, $part.Length)
    }
    return ,([byte[]]$stream.ToArray())
  } finally {
    $stream.Dispose()
  }
}

function Get-Keys([string]$Secret, [byte[]]$Salt) {
  try { [byte[]]$decodedSecret = [Convert]::FromBase64String($Secret) }
  catch { throw 'Invalid BUILD_BUNDLE_KEY.' }
  try {
    if ($decodedSecret.Length -ne 32 -or [Convert]::ToBase64String($decodedSecret) -cne $Secret) {
      throw 'Invalid BUILD_BUNDLE_KEY.'
    }
  } finally {
    if ($null -ne $decodedSecret) { [Array]::Clear($decodedSecret, 0, $decodedSecret.Length) }
  }
  $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new(
    $Secret,
    $Salt,
    200000,
    [Security.Cryptography.HashAlgorithmName]::SHA256
  )
  try {
    [byte[]]$material = $kdf.GetBytes(64)
    return @{
      Enc = [byte[]]$material[0..31]
      Mac = [byte[]]$material[32..63]
    }
  } finally {
    $kdf.Dispose()
    if ($null -ne $material) { [Array]::Clear($material, 0, $material.Length) }
  }
}

function New-MacInput(
  [byte[]]$Magic,
  [byte[]]$Context,
  [byte[]]$Salt,
  [byte[]]$InitializationVector,
  [byte[]]$Ciphertext
) {
  $stream = New-Object IO.MemoryStream
  try {
    foreach ($part in @($Magic, $Context, $Salt, $InitializationVector, $Ciphertext)) {
      $stream.Write($part, 0, $part.Length)
    }
    return ,([byte[]]$stream.ToArray())
  } finally {
    $stream.Dispose()
  }
}

function Test-FixedTimeEqual([byte[]]$Left, [byte[]]$Right) {
  if ($Left.Length -ne $Right.Length) { return $false }
  [int]$difference = 0
  for ($index = 0; $index -lt $Left.Length; $index++) {
    $difference = $difference -bor ($Left[$index] -bxor $Right[$index])
  }
  return ($difference -eq 0)
}

$envelope = $null
$magic = $null
$salt = $null
$initializationVector = $null
$tag = $null
$ciphertext = $null
$context = $null
$macInput = $null
$actualTag = $null
$plain = $null
$keys = $null
$temporaryPath = $null
try {
  $inputItem = Get-Item -LiteralPath $In
  [byte[]]$magic = [Text.Encoding]::ASCII.GetBytes($magicText)
  $minimumBytes = $magic.Length + 16 + 16 + 32 + 16
  if ($inputItem.Length -lt $minimumBytes -or $inputItem.Length -gt $maxEnvelopeBytes) {
    throw 'Invalid authenticated payload.'
  }
  $inputFullPath = $inputItem.FullName
  $outputFullPath = [IO.Path]::GetFullPath($Out)
  if ([string]::Equals($inputFullPath, $outputFullPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Input and output must be different files.'
  }
  if (Test-Path -LiteralPath $outputFullPath) { throw 'Output already exists.' }
  [byte[]]$envelope = [IO.File]::ReadAllBytes($inputFullPath)
  for ($index = 0; $index -lt $magic.Length; $index++) {
    if ($envelope[$index] -ne $magic[$index]) { throw 'Invalid authenticated payload.' }
  }

  $offset = $magic.Length
  [byte[]]$salt = $envelope[$offset..($offset + 15)]
  $offset += 16
  [byte[]]$initializationVector = $envelope[$offset..($offset + 15)]
  $offset += 16
  [byte[]]$tag = $envelope[$offset..($offset + 31)]
  $offset += 32
  [byte[]]$ciphertext = $envelope[$offset..($envelope.Length - 1)]
  if ($ciphertext.Length -lt 16 -or ($ciphertext.Length % 16) -ne 0) {
    throw 'Invalid authenticated payload.'
  }

  $keys = Get-Keys $K $salt
  [byte[]]$context = New-ContextBytes $ProjectId $Revision
  [byte[]]$macInput = New-MacInput $magic $context $salt $initializationVector $ciphertext
  $hmac = [Security.Cryptography.HMACSHA256]::new($keys.Mac)
  try { [byte[]]$actualTag = $hmac.ComputeHash($macInput) }
  finally { $hmac.Dispose() }
  if (-not (Test-FixedTimeEqual $tag $actualTag)) { throw 'Payload authentication failed.' }

  $aes = [Security.Cryptography.Aes]::Create()
  try {
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $keys.Enc
    $aes.IV = $initializationVector
    $decryptor = $aes.CreateDecryptor()
    try { [byte[]]$plain = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length) }
    finally { $decryptor.Dispose() }
  } finally {
    $aes.Dispose()
  }
  if ($plain.Length -gt $maxPlaintextBytes) { throw 'Decrypted payload exceeds the supported size limit.' }

  $outputDirectory = Split-Path -Parent $outputFullPath
  if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
  }
  $temporaryPath = "$outputFullPath.$([Guid]::NewGuid().ToString('N')).tmp"
  [IO.File]::WriteAllBytes($temporaryPath, $plain)
  [IO.File]::Move($temporaryPath, $outputFullPath)
  $temporaryPath = $null
} finally {
  if (-not [string]::IsNullOrWhiteSpace($temporaryPath)) {
    Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
  }
  foreach ($buffer in @(
    $envelope, $magic, $salt, $initializationVector, $tag, $ciphertext,
    $context, $macInput, $actualTag, $plain,
    $(if ($null -ne $keys) { $keys.Enc }), $(if ($null -ne $keys) { $keys.Mac })
  )) {
    if ($null -ne $buffer) { [Array]::Clear($buffer, 0, $buffer.Length) }
  }
}

Write-Host 'Prepared authenticated payload.'
