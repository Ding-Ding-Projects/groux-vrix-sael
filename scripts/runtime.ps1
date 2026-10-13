[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$In,
  [Parameter(Mandatory=$true)][string]$Out,
  [Parameter(Mandatory=$true)][string]$ProjectId,
  [Parameter(Mandatory=$true)][string]$Revision,
  [string]$K = $env:BUILD_BUNDLE_KEY
)

$ErrorActionPreference = 'Stop'
$script:EpbEnvelopeMagicText = 'EPBUNDLE2'
$script:EpbEnvelopeContextText = 'EPBCTX02'
$script:EpbEnvelopeSaltBytes = 16
$script:EpbEnvelopeIvBytes = 16
$script:EpbEnvelopeTagBytes = 32
$script:EpbEnvelopeKdfIterations = 200000
$script:EpbEnvelopeMaxPlaintextBytes = [int64]536870912
$script:EpbEnvelopeMaxBytes = [int64](
  $script:EpbEnvelopeMagicText.Length +
  $script:EpbEnvelopeSaltBytes +
  $script:EpbEnvelopeIvBytes +
  $script:EpbEnvelopeTagBytes +
  $script:EpbEnvelopeMaxPlaintextBytes +
  16
)

function Assert-EpbEnvelopeContext {
  param(
    [Parameter(Mandatory=$true)][string]$ProjectId,
    [Parameter(Mandatory=$true)][string]$Revision
  )

  if ($ProjectId -cnotmatch '^p[0-9a-f]{32}$') {
    throw 'ProjectId must be a lowercase opaque 128-bit identifier.'
  }
  if ($Revision -cnotmatch '^[0-9a-f]{32}$') {
    throw 'Revision must be a lowercase opaque 128-bit identifier.'
  }
}

function ConvertTo-EpbUInt32BigEndian {
  param([Parameter(Mandatory=$true)][uint32]$Value)

  [byte[]]$bytes = [BitConverter]::GetBytes($Value)
  if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
  return ,$bytes
}

function New-EpbEnvelopeContextBytes {
  param(
    [Parameter(Mandatory=$true)][string]$ProjectId,
    [Parameter(Mandatory=$true)][string]$Revision
  )

  Assert-EpbEnvelopeContext -ProjectId $ProjectId -Revision $Revision
  [byte[]]$contextMagic = [Text.Encoding]::ASCII.GetBytes($script:EpbEnvelopeContextText)
  [byte[]]$projectBytes = [Text.Encoding]::UTF8.GetBytes($ProjectId)
  [byte[]]$revisionBytes = [Text.Encoding]::UTF8.GetBytes($Revision)
  [byte[]]$projectLength = ConvertTo-EpbUInt32BigEndian ([uint32]$projectBytes.Length)
  [byte[]]$revisionLength = ConvertTo-EpbUInt32BigEndian ([uint32]$revisionBytes.Length)

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

function Get-EpbEnvelopeKeys {
  param(
    [Parameter(Mandatory=$true)][string]$Secret,
    [Parameter(Mandatory=$true)][byte[]]$Salt
  )

  if ([string]::IsNullOrWhiteSpace($Secret)) { throw 'The payload secret is required.' }
  try { [byte[]]$decodedSecret = [Convert]::FromBase64String($Secret) }
  catch { throw 'The payload secret is invalid.' }
  try {
    if ($decodedSecret.Length -ne 32 -or [Convert]::ToBase64String($decodedSecret) -cne $Secret) {
      throw 'The payload secret is invalid.'
    }
  } finally {
    if ($null -ne $decodedSecret) { [Array]::Clear($decodedSecret, 0, $decodedSecret.Length) }
  }
  if ($Salt.Length -ne $script:EpbEnvelopeSaltBytes) { throw 'The payload salt is invalid.' }
  $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new(
    $Secret,
    $Salt,
    $script:EpbEnvelopeKdfIterations,
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

function Test-EpbFixedTimeEqual {
  param(
    [Parameter(Mandatory=$true)][byte[]]$Left,
    [Parameter(Mandatory=$true)][byte[]]$Right
  )

  if ($Left.Length -ne $Right.Length) { return $false }
  [int]$difference = 0
  for ($index = 0; $index -lt $Left.Length; $index++) {
    $difference = $difference -bor ($Left[$index] -bxor $Right[$index])
  }
  return ($difference -eq 0)
}

# Shared streaming implementation, embedded verbatim in the public runtime.
function Invoke-EpbEnvelopeStream {
  param([string]$InputPath, [string]$OutputPath, [string]$Secret,
    [string]$ProjectId, [string]$Revision, [switch]$Encrypt)
  Assert-EpbEnvelopeContext -ProjectId $ProjectId -Revision $Revision
  $inputStream = $null; $outputStream = $null; $cryptoStream = $null
  $aes = $null; $transform = $null; $hmac = $null; $keys = $null
  $temporaryPath = $null
  [byte[]]$buffer = New-Object byte[] 65536
  [byte[]]$magic = [Text.Encoding]::ASCII.GetBytes($script:EpbEnvelopeMagicText)
  [byte[]]$salt = New-Object byte[] 16
  [byte[]]$initializationVector = New-Object byte[] 16
  [byte[]]$tag = New-Object byte[] 32
  [byte[]]$header = New-Object byte[] 73
  [byte[]]$context = New-EpbEnvelopeContextBytes -ProjectId $ProjectId -Revision $Revision
  try {
    $inputFullPath = (Get-Item -LiteralPath $InputPath -ErrorAction Stop).FullName
    $outputFullPath = [IO.Path]::GetFullPath($OutputPath)
    if ([string]::Equals($inputFullPath, $outputFullPath, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'Payload input and output must be different files.'
    }
    if (Test-Path -LiteralPath $outputFullPath) { throw 'Payload output already exists.' }
    # Keep one exclusive handle across both authentication and decryption passes.
    $inputStream = [IO.File]::Open($inputFullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    if ($Encrypt) {
      if ($inputStream.Length -gt $script:EpbEnvelopeMaxPlaintextBytes) { throw 'Payload input exceeds the supported size limit.' }
      $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
      try { $rng.GetBytes($salt); $rng.GetBytes($initializationVector) } finally { $rng.Dispose() }
    } else {
      if ($inputStream.Length -lt 89 -or $inputStream.Length -gt $script:EpbEnvelopeMaxBytes -or
          (($inputStream.Length - 73) % 16) -ne 0) { throw 'Invalid authenticated payload.' }
      $readHeader = 0
      while ($readHeader -lt $header.Length) {
        $read = $inputStream.Read($header, $readHeader, $header.Length - $readHeader)
        if ($read -eq 0) { throw 'Invalid authenticated payload.' }
        $readHeader += $read
      }
      for ($index = 0; $index -lt $magic.Length; $index++) {
        if ($header[$index] -ne $magic[$index]) { throw 'Invalid authenticated payload.' }
      }
      [Buffer]::BlockCopy($header, 9, $salt, 0, 16)
      [Buffer]::BlockCopy($header, 25, $initializationVector, 0, 16)
      [Buffer]::BlockCopy($header, 41, $tag, 0, 32)
    }
    $keys = Get-EpbEnvelopeKeys -Secret $Secret -Salt $salt
    $hmac = [Security.Cryptography.HMACSHA256]::new($keys.Mac)
    foreach ($part in @($magic, $context, $salt, $initializationVector)) {
      [void]$hmac.TransformBlock($part, 0, $part.Length, $null, 0)
    }
    if (-not $Encrypt) {
      while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        [void]$hmac.TransformBlock($buffer, 0, $read, $null, 0)
      }
      [void]$hmac.TransformFinalBlock([byte[]]@(), 0, 0)
      if (-not (Test-EpbFixedTimeEqual -Left $tag -Right $hmac.Hash)) { throw 'Payload authentication failed.' }
      $inputStream.Position = 73
    }
    # No plaintext path is opened before authentication succeeds.
    $outputDirectory = Split-Path -Parent $outputFullPath
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) { [void][IO.Directory]::CreateDirectory($outputDirectory) }
    $temporaryPath = "$outputFullPath.$([Guid]::NewGuid().ToString('N')).tmp"
    $outputStream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256; $aes.BlockSize = 128
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $keys.Enc; $aes.IV = $initializationVector
    if ($Encrypt) {
      foreach ($part in @($magic, $salt, $initializationVector, $tag)) { $outputStream.Write($part, 0, $part.Length) }
      $transform = $aes.CreateEncryptor()
      $cryptoStream = [Security.Cryptography.CryptoStream]::new($outputStream, $transform, [Security.Cryptography.CryptoStreamMode]::Write, $true)
      while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) { $cryptoStream.Write($buffer, 0, $read) }
      $cryptoStream.FlushFinalBlock()
      $cryptoStream.Dispose(); $cryptoStream = $null
      if ($outputStream.Length -gt $script:EpbEnvelopeMaxBytes) { throw 'Authenticated payload exceeds the supported size limit.' }
      $outputStream.Position = 73
      while (($read = $outputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        [void]$hmac.TransformBlock($buffer, 0, $read, $null, 0)
      }
      [void]$hmac.TransformFinalBlock([byte[]]@(), 0, 0)
      $outputStream.Position = 41
      $outputStream.Write($hmac.Hash, 0, 32)
    } else {
      $transform = $aes.CreateDecryptor()
      $cryptoStream = [Security.Cryptography.CryptoStream]::new($inputStream, $transform, [Security.Cryptography.CryptoStreamMode]::Read, $true)
      [int64]$plainBytes = 0
      while (($read = $cryptoStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $plainBytes += $read
        if ($plainBytes -gt $script:EpbEnvelopeMaxPlaintextBytes) { throw 'Decrypted payload exceeds the supported size limit.' }
        $outputStream.Write($buffer, 0, $read)
      }
      $cryptoStream.Dispose(); $cryptoStream = $null
    }
    $outputStream.Dispose(); $outputStream = $null
    [IO.File]::Move($temporaryPath, $outputFullPath)
    $temporaryPath = $null
  } finally {
    foreach ($resource in @($cryptoStream, $transform, $aes, $hmac, $outputStream, $inputStream)) {
      if ($null -ne $resource) { try { $resource.Dispose() } catch {} }
    }
    if (-not [string]::IsNullOrWhiteSpace($temporaryPath)) { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue }
    foreach ($part in @($buffer, $header, $salt, $initializationVector, $tag, $context,
        $(if ($null -ne $keys) { $keys.Enc }), $(if ($null -ne $keys) { $keys.Mac }))) {
      if ($null -ne $part) { [Array]::Clear($part, 0, $part.Length) }
    }
  }
}

function Write-EpbAuthenticatedEnvelope {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$InputPath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$Secret,
    [Parameter(Mandatory=$true)][string]$ProjectId,
    [Parameter(Mandatory=$true)][string]$Revision)
  Invoke-EpbEnvelopeStream @PSBoundParameters -Encrypt
}

function Read-EpbAuthenticatedEnvelope {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$InputPath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$Secret,
    [Parameter(Mandatory=$true)][string]$ProjectId,
    [Parameter(Mandatory=$true)][string]$Revision)
  Invoke-EpbEnvelopeStream @PSBoundParameters
}

function Test-EpbAuthenticatedEnvelopeHeader {
  param([Parameter(Mandatory=$true)][string]$InputPath)

  if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { return $false }
  [byte[]]$magic = [Text.Encoding]::ASCII.GetBytes($script:EpbEnvelopeMagicText)
  $stream = [IO.File]::OpenRead((Resolve-Path -LiteralPath $InputPath).Path)
  try {
    if ($stream.Length -lt ($magic.Length + $script:EpbEnvelopeSaltBytes +
        $script:EpbEnvelopeIvBytes + $script:EpbEnvelopeTagBytes + 16)) { return $false }
    [byte[]]$header = New-Object byte[] $magic.Length
    if ($stream.Read($header, 0, $header.Length) -ne $header.Length) { return $false }
    for ($index = 0; $index -lt $magic.Length; $index++) {
      if ($header[$index] -ne $magic[$index]) { return $false }
    }
    return $true
  } finally {
    $stream.Dispose()
  }
}

Read-EpbAuthenticatedEnvelope -InputPath $In -OutputPath $Out -Secret $K -ProjectId $ProjectId -Revision $Revision
Write-Host 'Prepared authenticated payload.'
