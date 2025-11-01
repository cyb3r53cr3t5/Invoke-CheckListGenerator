function Invoke-CheckListGenerator{
    <#
    .SYNOPSIS
    Скрипт Invoke-CheckListGenerator преобразует результаты Cypher-запросов BloodHound в структурированные чек-листы Obsidian,
    позволяя автоматизировать процесс аудита безопасности Active Directory и отслеживать прогресс исправления уязвимостей.  
    .DESCRIPTION
    Скрипт подключается к базе данных Neo4j BloodHound Neo4j, выполняет серию проверок безопасности через запросы Cypher и затем
    формирует два файла в формате markdown для Obsidian. Первый файл — это результаты проверок, которые можно использовать для работы.
    Второй файл, содержит задачи для чек-листа. Если результат проверки отсутствует, то задача помечается как выполненная со статусом "Провал".
    Если проверка является самостоятельной SelfCheck = True и у нее есть результат она помечается как выполненная со статусом успех.
    SelfCheck - проверки результаты, которых могут быть использованы в  других векторах.
    .PARAMETER server
    Параметр по умолчанию "localhost", устанавливает адрес базы данных neo4j.
    .PARAMETER dbUser
    Параметр по умолчанию "neo4j", имя пользователя для подключения к базе данных.
    .PARAMETER dbPassword
    Пароль для подключения к базе данных.
    .PARAMETER dbName
    Параметр по умолчанию "neo4j", имя базы данных. При использовании плагина "dozerdb" можно указывать отличное от neo4j имя базы данных.
    .PARAMETER fileName
    Параметр по умолчанию "queries.json", файл где храняться запросы Cypher.
    .EXAMPLE
    Invoke-CheckListGenerator -dbPassword Qwerty123 -dbName
    Простой запуск, где указывается только пароль к базе данных.
    .EXAMPLE
    Invoke-CheckListGenerator -server 10.10.10.10 -dbPassword Qwerty123 -dbName testdb
    Запуск с параметрами если параметры для подключения к базе данных отличаются от стандарнтых.
    .NOTES
    Большая часть запросов требует использоватьние результатов ShaprHound версии 2.
    Автор: Неверов Дмитрий
    Версия: 0.6
    #>

    [CmdletBinding()]
    Param (
        [Parameter (Mandatory=$false, Position=0)]
        [string]$server = "localhost",

        [Parameter (Mandatory=$false, Position=1)]
        [string]$dbUser = "neo4j",

        [Parameter (Mandatory=$false, Position=2)]
        [string]$dbPassword,

        [Parameter (Mandatory=$false, Position=3)]
        [string]$dbName = "neo4j",

        [Parameter (Mandatory=$false, Position=3)]
        [string]$fileName = "queries.json"
    )

    # Формирование строики для подключения к базе данных
    [string]$Neo4jUrl = "http://$server`:7474/db/$dbName/tx/commit"

    # Файлы для записи
    $OutputFile = "BloodHound_Checklist.md"
    $QueryFile = "BloodHound_QueryResult.md"

    # Создание пустых массивов
    $queryresultContent = @()
    $checklistContent = @()
    
    # Проверка что файл существует
    if(Test-Path -Path $fileName){
        # Проверка что указан json файл
        if (-not ([System.IO.Path]::GetExtension($fileName) -eq ".json")) {
            Write-Host -ForegroundColor Red "[ERROR] File $fileName is not a json file"
            break
        }
    }
    else {
        Write-Host -ForegroundColor Red "[ERROR] File $fileName doesn't exist"
        break
    }

    
    # Чтение файла с запросами
    $jsonContent = Get-Content -Path $filename -Raw -Encoding UTF8 | ConvertFrom-Json
    

    # Выполнение проверок 
    foreach ($check in $jsonContent.queries) 
    {
        [array]$results = Invoke-BloodHoundQuery -Query $check.query -Uri $Neo4jUrl -User $dbUser -Password $dbPassword
        
        if($results.count -gt 0)
        {
            Write-Host -ForegroundColor Green "[+] Для проверки '$($check.name)' было найдено $($results.count)"
        }
        else
        {
            Write-Host "[-] Для проверки '$($check.name)' было найдено $($results.count)"
        }

        
        $resultRow = $results.row
        
        # Добавление данных в заметки только для которых есть результат или selfcheck = true
        if ($resultRow -and $results.Count -gt 0 -or $check.selfcheck -eq $True) {
            # Ограничение вывода путей 10 первыми строками
            if($results.Count -gt 10 -and $check.type -eq "Path")
            {
                $resultRow = $results.row | Select-Object -First 10

                $msglimit =">[!attention] Внимание
                            > Для путей выводится первые 10 записе, чтобы не перезагружать заметки.
                            "
            }
            else {
                $msglimit = ""
            }

            # Формирование блока для Заметок

            # Из запроса уберем лишние знаки табуляции
            $cypherQuery = $check.query
            #$cypherQuery = $cypherQuery -replace '(?s)REDUCE.*$', 'p'
            $cypherQuery = $cypherQuery -replace '(?s)REDUCE\(.*?name\)', 'p'
            $cypherQuery = $cypherQuery -replace '.name$', ''
            $msglimit = $msglimit -replace '    ', ''

            if ($resultRow -ne $null) 
            {
                $queryresultContent += @"
### $($check.Name)
**Описание:** $($check.Description)

**Cypher запрос:** 
``````cypher
$($cypherQuery)
``````

**Всего записей:** $($results.Count)

**Результат**
``````
$($resultRow -join [Environment]::NewLine)
``````
$msglimit
"@
            }
        }

        # Добавление чек листа в список
        if($resultRow -eq $null)
        {
            $checked = "X"
            $state = "провал"
            $loglink = ""
            $notes = ""
            $comments = "Нет узлов или связей"
        }
        elseif($resultRow -ne $null -and $check.SelfCheck -eq $True){
            $checked = "X"
            $state = "успех"
            $loglink = "[[02 Заметки#$($check.Name)]]"
            $notes = ""
            $comments = ""
        }
        else {
            $checked = " "
            $state = ""
            $loglink = ""
            $notes = "[[02 Заметки#$($check.Name)]]"
            $comments = ""
        }


        # Формирование блока для Чек листа
        $checklistContent += @"
- [$($checked)] [name:: $($check.Name)]
[state:: $($state)]
[loglink:: $($loglink)]
[notes:: $($notes)]
[comments:: $($comments)]

"@

    }

    # Save to file
    $checklistContent | Out-File -FilePath $OutputFile  -Encoding UTF8
    $queryresultContent | Out-File -FilePath $QueryFile -Encoding UTF8

    #$queryresultContent

    #$checklistContent
    Write-Host "`n[*] BloodHound чек лист и заметки сгенерированы" -ForegroundColor Green
}

# Function to execute Cypher query
function Invoke-BloodHoundQuery {
    param(
        [string]$Query,
        [string]$Uri = $Neo4jUri,
        [string]$User = $Neo4jUser,
        [string]$Password = $Neo4jPassword
    )
    
    $authHeader = [Convert]::ToBase64String(
        [Text.Encoding]::ASCII.GetBytes("${User}:${Password}")
    )
    
    $body  = @{statements=@(@{statement=$query})} | ConvertTo-Json 
        
    try {
        $response = Invoke-WebRequest -Uri $Uri -Method Post `
            -ContentType "application/json; charset=utf-8" `
            -Headers @{Authorization = "Basic $authHeader"} `
            -Body $body
        
        if ($response.errors) {
            Write-Warning "Query error: $($response.errors[0].message)"
            return $null
        }
        
        $data = convertFromISOToUtf8($response.Content) |ConvertFrom-Json
         
        return $data.results.data
        
    }
    catch {
        Write-Error "Failed to execute query: $_"
        return $null
    }
}

# https://internet-lab.ru/powershell_from_ISO-8859-1_to_UTF-8
function convertFromISOToUtf8([string] $String) {
    [System.Text.Encoding]::UTF8.GetString(
        [System.Text.Encoding]::GetEncoding(28591).GetBytes($String)
    )
}