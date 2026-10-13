[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$DiscussionId,
  [Parameter(Mandatory=$true)][string]$ProjectId,
  [Parameter(Mandatory=$true)][string]$Revision,
  [Parameter(Mandatory=$true)][string]$BuilderSha,
  [Parameter(Mandatory=$true)][string]$JobName,
  [Parameter(Mandatory=$true)][ValidateSet('build','release')][string]$Workflow,
  [Parameter(Mandatory=$true)][ValidateSet('in_progress','completed','skipped')][string]$Status,
  [string]$Conclusion = '',
  [string]$Release = ''
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($env:PRIVATE_RELEASE_TOKEN)) {
  throw 'missing private Discussion credential'
}
if ([string]::IsNullOrWhiteSpace($DiscussionId)) {
  throw 'missing status Discussion id'
}
if ($JobName -ne "$Workflow-$ProjectId") {
  throw 'status job identity does not match the opaque project and phase'
}
if ($BuilderSha -notmatch '^[0-9a-fA-F]{40,64}$') {
  throw 'status builder revision is invalid'
}
$env:GH_TOKEN = $env:PRIVATE_RELEASE_TOKEN

function ConvertFrom-Base64Url([string]$Value) {
  $base64 = $Value.Replace('-', '+').Replace('_', '/')
  switch ($base64.Length % 4) {
    2 { $base64 += '==' }
    3 { $base64 += '=' }
  }
  [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64))
}

$updatedAt = [DateTime]::UtcNow.ToString('o')
$runId = "$env:GITHUB_RUN_ID`:$env:GITHUB_RUN_ATTEMPT"
$runUrl = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
$record = [ordered]@{
  builderSha = $BuilderSha
  projectId = $ProjectId
  jobName = $JobName
  status = $Status
  conclusion = if ([string]::IsNullOrWhiteSpace($Conclusion)) { $null } else { $Conclusion }
  updatedAt = $updatedAt
  runId = $runId
  runUrl = $runUrl
  workflow = $Workflow
  revision = $Revision
  release = if ([string]::IsNullOrWhiteSpace($Release)) { $null } else { $Release }
}
$json = $record | ConvertTo-Json -Compress
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$marker = "<!-- epb-status:v1:$encoded -->"

# The timestamp is mutable data, so dedupe the decoded stable milestone identity.
$query = 'query($id:ID!, $cursor:String) { node(id:$id) { ... on Discussion { comments(first:100, after:$cursor) { nodes { body } pageInfo { hasNextPage endCursor } } } } }'
$cursor = $null
$alreadyPosted = $false
do {
  $arguments = @('api', 'graphql', '-f', "query=$query", '-f', "id=$DiscussionId")
  if ($cursor) { $arguments += @('-f', "cursor=$cursor") }
  $raw = gh @arguments 2>$null
  if ($LASTEXITCODE -ne 0) { throw 'Discussion comment lookup failed' }
  $connection = ($raw | ConvertFrom-Json).data.node.comments
  if ($null -eq $connection) { throw 'status Discussion was not found' }
  foreach ($comment in @($connection.nodes)) {
    foreach ($match in [regex]::Matches([string]$comment.body, '<!-- epb-status:v1:([A-Za-z0-9_-]+) -->')) {
      try { $seen = ConvertFrom-Base64Url $match.Groups[1].Value | ConvertFrom-Json } catch { continue }
      if ($seen.projectId -eq $ProjectId -and
          $seen.workflow -eq $Workflow -and
          $seen.jobName -eq $JobName -and
          $seen.runId -eq $runId -and
          $seen.status -eq $Status) {
        $alreadyPosted = $true
        break
      }
    }
    if ($alreadyPosted) { break }
  }
  $cursor = $connection.pageInfo.endCursor
} while (-not $alreadyPosted -and $connection.pageInfo.hasNextPage)

if ($alreadyPosted) {
  Write-Host "$Workflow/$Status status comment already exists for this run attempt"
  return
}

$icon = switch ($Status) {
  'in_progress' { '⏳' }
  'skipped' { '⏭️' }
  default { if ($Conclusion -eq 'success') { '✅' } else { '❌' } }
}
$phaseLabel = if ($Workflow -eq 'build') { 'Build / 建置' } else { 'Release / 發佈' }
$conclusionDisplay = if ([string]::IsNullOrWhiteSpace($Conclusion)) { '_pending / 等候中_' } else { "``$Conclusion``" }
$releaseDisplay = if ([string]::IsNullOrWhiteSpace($Release)) { '_not available / 未有_' } else { "``$Release``" }
$body = @"
$marker
### $icon $phaseLabel

| Field / 欄位 | Value / 內容 |
|---|---|
| Status / 狀態 | ``$Status`` |
| Conclusion / 結果 | $conclusionDisplay |
| Project / 專案 | ``$ProjectId`` |
| Revision / 修訂 | ``$Revision`` |
| Builder revision / 建置器修訂 | ``$BuilderSha`` |
| Job / 工作 | ``$JobName`` |
| Release / 版本 | $releaseDisplay |
| Updated / 更新 | $updatedAt |
| Run / 執行 | [Open log / 開啟紀錄]($runUrl) |

This milestone is append-only; later events get their own comments, so the history keeps its receipts.

呢個里程碑只會追加；之後嘅事件各有新留言，條時間線唔會偷偷改口供。
"@
$mutation = 'mutation($discussionId:ID!, $body:String!) { addDiscussionComment(input:{discussionId:$discussionId, body:$body}) { comment { id } } }'
gh api graphql -f "query=$mutation" -f "discussionId=$DiscussionId" -f "body=$body" *> $null
if ($LASTEXITCODE -ne 0) { throw 'Discussion status append failed' }
