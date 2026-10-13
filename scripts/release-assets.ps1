# Private release manifests never enter public metadata or diagnostics.
function New-EpbNormalRelease {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Tag, [Parameter(Mandatory)][string]$SourceSha,
    [Parameter(Mandatory)][string[]]$Assets, [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$Notes)
  if ($SourceSha -cnotmatch '^[0-9a-f]{40}$' -or $Tag -cnotmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$' -or
      $env:TARGET_RELEASE_REPO -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
      [string]::IsNullOrWhiteSpace($env:PRIVATE_RELEASE_TOKEN) -or $env:EXPECTED_REVISION -cne $env:PROJECT_REV -or
      $env:GITHUB_RUN_ATTEMPT -cnotmatch '^[1-9][0-9]{0,9}$') {
    throw 'Normal release source, target or revision authority is unavailable.'
  }
  $policy = Get-EpbAssetPolicy -Json $env:RELEASE_ASSET_POLICY -Revision $env:PROJECT_REV
  $inventory = @(); $paths = @()
  foreach ($path in $Assets) {
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Release asset must be a regular file.' }
    $paths += $item.FullName
    $inventory += [ordered]@{name=$item.Name;bytes=[long]$item.Length;sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
  }
  # Validate every local byte declaration even for explicitly optional legacy manifests.
  $null = ConvertTo-EpbAssetPayload -Assets $inventory -ProjectId $env:PROJECT_ID -Revision $env:PROJECT_REV -BuilderSha $env:BUILDER_SHA -RunId $env:GITHUB_RUN_ID
  $provenance = [ordered]@{project_id=$env:PROJECT_ID;revision=$env:PROJECT_REV;builder_sha=$env:BUILDER_SHA;run_id=$env:GITHUB_RUN_ID;run_attempt=$env:GITHUB_RUN_ATTEMPT} | ConvertTo-Json -Compress
  if ($Notes -match '<!-- epb-(?:release|source|assets|workflow-timing):') { throw 'Reserved release evidence already exists in supplied notes.' }
  $marker = '<!-- epb-release:v2:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($provenance)).TrimEnd('=').Replace('+','-').Replace('/','_') + ' -->'
  $body = $Notes.TrimEnd() + "`n`n$marker`n<!-- epb-source:v1:$SourceSha -->"
  if ($policy.required) { $body += "`n" + (New-ReleaseAssetManifestMarker -Assets $inventory) }
  $body += "`n`nPublication verification: incomplete until the workflow finalizer verifies source, assets and timing."
  $oldToken = $env:GH_TOKEN
  try {
    $env:GH_TOKEN = $env:PRIVATE_RELEASE_TOKEN
    $raw = @(gh api --hostname github.com "repos/$env:TARGET_RELEASE_REPO/commits/$SourceSha" 2>$null)
    if ($LASTEXITCODE -ne 0 -or (($raw -join "`n") | ConvertFrom-Json).sha -cne $SourceSha) { throw 'Exact private source commit is unavailable.' }
    $raw = @(gh api --hostname github.com "repos/$env:TARGET_RELEASE_REPO/compare/$SourceSha...main" 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Private main containment proof is unavailable.' }
    $comparison = ($raw -join "`n") | ConvertFrom-Json
    if ($comparison.status -cnotin @('ahead','identical') -or $comparison.merge_base_commit.sha -cne $SourceSha) {
      throw 'Private main does not contain the intended source commit.'
    }
    # A successful ref inventory must prove the new tag does not exist. Never reuse a tag.
    $raw = @(gh api --hostname github.com "repos/$env:TARGET_RELEASE_REPO/git/matching-refs/tags/$Tag" 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Private tag inventory is unavailable.' }
    if (@(($raw -join "`n" | ConvertFrom-Json) | Where-Object { $_.ref -ceq "refs/tags/$Tag" }).Count -gt 0) { throw 'Private release tag already exists.' }
    $refJson = @{ref="refs/tags/$Tag";sha=$SourceSha} | ConvertTo-Json -Compress
    $raw = @($refJson | gh api --hostname github.com --method POST "repos/$env:TARGET_RELEASE_REPO/git/refs" --input - 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Create-only private source tag allocation failed.' }
    $createdRef = ($raw -join "`n") | ConvertFrom-Json
    if ($createdRef.ref -cne "refs/tags/$Tag" -or $createdRef.object.sha -cne $SourceSha) { throw 'Allocated private tag does not match the exact source.' }
    # gh release create with assets internally stages a draft. Use explicit normal creation.
    $json = @{tag_name=$Tag;target_commitish=$SourceSha;name=$Title;body=$body;draft=$false;prerelease=$false;make_latest='false'} | ConvertTo-Json -Compress
    $raw = @($json | gh api --hostname github.com --method POST "repos/$env:TARGET_RELEASE_REPO/releases" --input - 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Normal private release creation failed; source tag remains preserved.' }
    $created = ($raw -join "`n") | ConvertFrom-Json
    if ([string]$created.id -cnotmatch '^[1-9][0-9]{0,18}$' -or $created.draft -isnot [bool] -or
        $created.prerelease -isnot [bool] -or $created.draft -or $created.prerelease -or $created.tag_name -cne $Tag -or
        [string]::IsNullOrWhiteSpace([string]$created.published_at)) { throw 'Normal private release creation readback is invalid.' }
    $releaseId = [int64]$created.id
    foreach ($path in $paths) {
      $assetName = [Uri]::EscapeDataString([IO.Path]::GetFileName($path))
      $uploadRoute = "https://uploads.github.com/repos/$env:TARGET_RELEASE_REPO/releases/$releaseId/assets?name=$assetName"
      $raw = @(gh api --hostname github.com --method POST $uploadRoute --input $path -H 'Content-Type:application/octet-stream' 2>$null)
      if ($LASTEXITCODE -ne 0) { throw 'Normal private release upload failed; publication remains incomplete.' }
    }
    $raw = @(gh api --hostname github.com "repos/$env:TARGET_RELEASE_REPO/releases/$releaseId" 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Normal private release upload readback is unavailable.' }
    $uploaded = ($raw -join "`n") | ConvertFrom-Json
    if ([int64]$uploaded.id -ne $releaseId -or $uploaded.tag_name -cne $Tag -or
        $uploaded.draft -isnot [bool] -or $uploaded.prerelease -isnot [bool] -or $uploaded.draft -or $uploaded.prerelease) {
      throw 'Normal private release identity changed after upload.'
    }
    $null = Assert-ReleaseAssetInventory -Release $uploaded -Manifest ([pscustomobject]@{assets=$inventory})
  } finally {
    $env:GH_TOKEN = $oldToken
  }
}
function Get-EpbAssetPolicy {
  param([string]$Json, [string]$Revision)
  if ([string]::IsNullOrWhiteSpace($Json) -or $Json.Length -gt 2048) { throw 'Release asset policy is unavailable.' }
  try { $policy = $Json | ConvertFrom-Json -ErrorAction Stop } catch { throw 'Release asset policy is invalid.' }
  if ((@($policy.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'key,required,revision,version' -or
      $policy.version -ne 1 -or $policy.required -isnot [bool] -or
      [string]$policy.revision -cnotmatch '^[0-9a-f]{32}$' -or [string]$policy.revision -cne $Revision) {
    throw 'Release asset policy does not match the selected revision.'
  }
  if ($policy.required) {
    if ($policy.key -isnot [string] -or $policy.key -cnotmatch '^[A-Za-z0-9+/]{43}=$') { throw 'Release asset signing authority is unavailable.' }
    $key = [Convert]::FromBase64String($policy.key)
    try { if ($key.Length -ne 32 -or [Convert]::ToBase64String($key) -cne $policy.key) { throw 'Release asset signing authority is invalid.' } }
    finally { [Array]::Clear($key, 0, $key.Length) }
  } elseif ($null -ne $policy.key) { throw 'Optional release asset policy must not carry a key.' }
  $canonical = [ordered]@{version=1;revision=[string]$policy.revision;required=[bool]$policy.required;key=$policy.key} | ConvertTo-Json -Compress
  if ($canonical -cne $Json) { throw 'Release asset policy must use its exact canonical schema.' }
  return $policy
}

function Get-EpbAssetMac {
  param([string]$Key, [byte[]]$Bytes)
  $keyBytes = [Convert]::FromBase64String($Key)
  $hmac = [Security.Cryptography.HMACSHA256]::new($keyBytes)
  try { return ([BitConverter]::ToString($hmac.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $hmac.Dispose(); [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
}

function ConvertTo-EpbAssetPayload {
  param([object[]]$Assets, [string]$ProjectId, [string]$Revision, [string]$BuilderSha, [string]$RunId)
  if ($ProjectId -cnotmatch '^p[0-9a-f]{32}$' -or $Revision -cnotmatch '^[0-9a-f]{32}$' -or
      $BuilderSha -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or $RunId -cnotmatch '^[1-9][0-9]{0,19}$') {
    throw 'Release asset provenance is invalid.'
  }
  if ($Assets.Count -lt 1 -or $Assets.Count -gt 64) { throw 'Release asset count is outside its bound.' }
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $sorted = [Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
  [long]$total = 0
  foreach ($asset in $Assets) {
    $keys = if ($asset -is [Collections.IDictionary]) { @($asset.Keys) } else { @($asset.PSObject.Properties.Name) }
    if ((@($keys | Sort-Object) -join ',') -cne 'bytes,name,sha256' -or
        $asset.name -isnot [string] -or $asset.name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$' -or
        -not $seen.Add($asset.name) -or $asset.sha256 -isnot [string] -or $asset.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        ($asset.bytes -isnot [int] -and $asset.bytes -isnot [long]) -or
        $asset.bytes -lt 1 -or $asset.bytes -gt 1073741824) {
      throw 'Release asset declaration is invalid.'
    }
    $total += [long]$asset.bytes
    if ($total -gt 1400000000) { throw 'Release asset aggregate exceeds its bound.' }
    $sorted.Add($asset.name, [ordered]@{name=[string]$asset.name;bytes=[long]$asset.bytes;sha256=[string]$asset.sha256})
  }
  return [ordered]@{version=1;project_id=$ProjectId;revision=$Revision;builder_sha=$BuilderSha;run_id=$RunId;assets=@($sorted.Values)}
}

function New-ReleaseAssetManifestMarker {
  param([object[]]$Assets, [string]$PolicyJson=$env:RELEASE_ASSET_POLICY,
    [string]$ProjectId=$env:PROJECT_ID, [string]$Revision=$env:PROJECT_REV,
    [string]$BuilderSha=$env:BUILDER_SHA, [string]$RunId=$env:GITHUB_RUN_ID)
  $policy = Get-EpbAssetPolicy -Json $PolicyJson -Revision $Revision
  if (-not $policy.required) { throw 'Release asset manifest signing is not enabled.' }
  $payload = ConvertTo-EpbAssetPayload -Assets $Assets -ProjectId $ProjectId -Revision $Revision -BuilderSha $BuilderSha -RunId $RunId
  $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress -Depth 8))
  $payload.mac = Get-EpbAssetMac -Key $policy.key -Bytes $bytes
  $json = $payload | ConvertTo-Json -Compress -Depth 8
  if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 32768) { throw 'Release asset manifest exceeds its bound.' }
  return '<!-- epb-assets:v1:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)).TrimEnd('=').Replace('+','-').Replace('/','_') + ' -->'
}

function Read-ReleaseAssetManifest {
  param([string]$Body, [object]$Policy, [string]$ProjectId, [string]$Revision, [string]$BuilderSha, [string]$RunId)
  if (-not $Policy.required) { return $null }
  if ($Body.Length -gt 125000) { throw 'Private release notes exceed their bound.' }
  $markers = [regex]::Matches($Body, '(?m)^<!-- epb-assets:v1:([A-Za-z0-9_-]{1,43691}) -->\r?$')
  if ($markers.Count -ne 1 -or [regex]::Matches($Body, '<!-- epb-assets:').Count -ne 1) { throw 'Exactly one private asset manifest is required.' }
  $encoded = $markers[0].Groups[1].Value
  if ($encoded.Length % 4 -eq 1) { throw 'Private asset manifest encoding is invalid.' }
  try {
    $bytes = [Convert]::FromBase64String($encoded.Replace('-','+').Replace('_','/') + ('=' * ((4 - $encoded.Length % 4) % 4)))
    if ($bytes.Length -gt 32768 -or [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_') -cne $encoded) { throw 'encoding' }
    $json = [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
    $manifest = $json | ConvertFrom-Json -ErrorAction Stop
  } catch { throw 'Private asset manifest encoding is invalid.' }
  if ((@($manifest.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'assets,builder_sha,mac,project_id,revision,run_id,version' -or
      $manifest.version -ne 1 -or $manifest.project_id -cne $ProjectId -or $manifest.revision -cne $Revision -or
      $manifest.builder_sha -cne $BuilderSha -or $manifest.run_id -cne $RunId -or
      $manifest.mac -isnot [string] -or $manifest.mac -cnotmatch '^[0-9a-f]{64}$' -or $manifest.assets -isnot [array]) {
    throw 'Private asset manifest provenance or schema is invalid.'
  }
  $payload = ConvertTo-EpbAssetPayload -Assets $manifest.assets -ProjectId $ProjectId -Revision $Revision -BuilderSha $BuilderSha -RunId $RunId
  $expected = Get-EpbAssetMac -Key $Policy.key -Bytes ([Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress -Depth 8)))
  $difference = 0
  for ($i=0; $i -lt 64; $i++) { $difference = $difference -bor ([int][char]$expected[$i] -bxor [int][char]$manifest.mac[$i]) }
  $payload.mac = $manifest.mac
  if ($difference -ne 0 -or ($payload | ConvertTo-Json -Compress -Depth 8) -cne $json) { throw 'Private asset manifest authentication failed.' }
  return $manifest
}

function Assert-ReleaseAssetInventory {
  param([object]$Release, [object]$Manifest)
  if ($null -eq $Manifest) { return '' }
  $assets = @($Release.assets)
  if ($assets.Count -ne $Manifest.assets.Count) { throw 'Private release asset inventory differs from its declaration.' }
  $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $snapshot = [Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
  foreach ($asset in $assets) {
    $declared = @($Manifest.assets | Where-Object { $_.name -ceq $asset.name })
    if ([string]$asset.id -cnotmatch '^[1-9][0-9]{0,19}$' -or -not $ids.Add([string]$asset.id) -or
        -not $names.Add([string]$asset.name) -or $declared.Count -ne 1 -or $asset.state -cne 'uploaded' -or
        [long]$asset.size -ne [long]$declared[0].bytes) { throw 'Private release asset identity or size is invalid.' }
    $snapshot.Add([string]$asset.name, [ordered]@{id=[string]$asset.id;name=[string]$asset.name;bytes=[long]$asset.size;sha256=[string]$declared[0].sha256})
  }
  return (@($snapshot.Values) | ConvertTo-Json -Compress -Depth 6)
}

function Initialize-EpbAssetStream {
  if ('EpbPrivateAssetStream' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
public static class EpbPrivateAssetStream {
  static async Task Drain(Stream stream, CancellationToken ct) {
    var buffer = new byte[4096]; long total = 0; int count;
    while ((count = await stream.ReadAsync(buffer.AsMemory(), ct)) > 0) {
      total += count; if (total > 32768) throw new InvalidDataException("Private download diagnostic limit exceeded.");
    }
  }
  static async Task Hash(Stream stream, long expected, string digest, CancellationToken ct) {
    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    var buffer = new byte[65536]; long total = 0; int count;
    while ((count = await stream.ReadAsync(buffer.AsMemory(), ct)) > 0) {
      total += count; if (total > expected) throw new InvalidDataException("Private download size differs.");
      hash.AppendData(buffer, 0, count);
    }
    var actual = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    if (total != expected || actual != digest) throw new InvalidDataException("Private download content differs.");
  }
  public static async Task Verify(ProcessStartInfo start, long expected, string digest, int timeoutMs) {
    using var timeout = new CancellationTokenSource(timeoutMs);
    using var process = new Process { StartInfo = start };
    try {
      if (!process.Start()) throw new InvalidOperationException("Private download unavailable.");
      var output = Hash(process.StandardOutput.BaseStream, expected, digest, timeout.Token);
      var errors = Drain(process.StandardError.BaseStream, timeout.Token);
      var exit = process.WaitForExitAsync(timeout.Token);
      var pending = new System.Collections.Generic.List<Task> { output, errors, exit };
      while (pending.Count > 0) { var task = await Task.WhenAny(pending); await task; pending.Remove(task); }
      if (process.ExitCode != 0) throw new InvalidOperationException("Private download failed.");
    } finally {
      timeout.Cancel();
      try { if (!process.HasExited) process.Kill(true); } catch (InvalidOperationException) { }
    }
  }
}
'@
}

function Test-ReleaseAssetDownloads {
  param([object]$Release, [object]$Manifest, [string]$Repository, [string]$Credential)
  if ($null -eq $Manifest) { return }
  if ($Repository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or [string]::IsNullOrWhiteSpace($Credential)) { throw 'Private download authority is unavailable.' }
  [void](Assert-ReleaseAssetInventory -Release $Release -Manifest $Manifest)
  Initialize-EpbAssetStream
  $deadline = [Diagnostics.Stopwatch]::StartNew()
  foreach ($asset in @($Release.assets)) {
    $remaining = 900000 - [int]$deadline.ElapsedMilliseconds
    if ($remaining -le 0) { throw 'Private asset verification exceeded its overall deadline.' }
    $declared = @($Manifest.assets | Where-Object { $_.name -ceq $asset.name })[0]
    $start = [Diagnostics.ProcessStartInfo]::new('gh')
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    foreach ($argument in @('api', "repos/$Repository/releases/assets/$($asset.id)", '--hostname', 'github.com', '-H', 'Accept: application/octet-stream')) { $start.ArgumentList.Add($argument) }
    foreach ($name in @('RELEASE_ASSET_POLICY','PRIVATE_RELEASE_TOKEN','BUILD_BUNDLE_KEY','GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN','GH_DEBUG','GH_TRACE','GH_API_HOST')) { [void]$start.Environment.Remove($name) }
    $start.Environment['GH_TOKEN']=$Credential; $start.Environment['GH_PROMPT_DISABLED']='1'
    try { [EpbPrivateAssetStream]::Verify($start, [long]$declared.bytes, [string]$declared.sha256, [Math]::Min(180000,$remaining)).GetAwaiter().GetResult() }
    catch { throw 'Private asset byte verification failed.' }
  }
}
