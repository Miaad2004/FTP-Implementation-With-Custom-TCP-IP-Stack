$serverPath = "./"
$venvPath = "$serverPath\venv"
$requirementsFile = "$serverPath\requirements.txt"
$serverScript = "$serverPath\start_server.py"
$minPythonVersion = [version]"3.6"

function Check-PythonVersion {
    $pythonVersion = & python --version 2>&1
    if ($pythonVersion -match "Python (\d+\.\d+\.\d+)") {
        $currentVersion = [version]$matches[1]
        if ($currentVersion -lt $minPythonVersion) {
            Write-Error "Python $($minPythonVersion) or higher is required. Current version: $currentVersion"
            exit 1
        } else {
            Write-Output "Python version $currentVersion is sufficient."
        }
    } else {
        Write-Error "Unable to determine Python version."
        exit 1
    }
}

function Setup-Venv {
    if (-Not (Test-Path $venvPath)) {
        Write-Output "Setting up virtual environment..."
        python -m venv $venvPath
        Write-Output "Virtual environment setup complete."
    } else {
        Write-Output "Virtual environment already exists."
    }
    $env:Path = "$venvPath\Scripts;$env:Path"
}

function Install-Requirements {
    Write-Output "Installing Python packages from requirements.txt..."
    $requirements = Get-Content $requirementsFile
    
    foreach ($package in $requirements) {
        Write-Output "Installing package: $package"
        & "$venvPath\Scripts\pip.exe" install $package

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to install package: $package"
        }
        
        else {
            Write-Output "Successfully installed package: $package"
        }
    }
}


function Start-Server {
    Write-Output "Starting the server..."
    & "$venvPath\Scripts\python.exe" $serverScript
}

Write-Output "Deploying the server..."
Check-PythonVersion
Setup-Venv
Install-Requirements
Start-Server
Write-Output "Server deployed successfully."