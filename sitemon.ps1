##############################  User defined params ############################################################

## The target URL to monitor
#$uri = "https://internal-app.domain.local/"
$uri = "https://www.google.co.uk/"
#$uri = "http://www.bing.com/"
#$uri = "https://login.microsoftonline.com/"

## Ignore SSL/TLS errors when attempting connection to trunk by IP instead of fqdn. Useful for split DNS scenarios
$IgnoreTLS = $true

## Frequency of web query in seconds. Do not set this too low or you risk running into DOS protection
$Interval = 8

## Query timeout in seconds - TCP Handsahe is 21
$TimeOut = 21

## Stop Trace and monitoring if site problems are detected 
$StopOnFailure = $false

## Drive and path that we'll dump all of our data to
$DataPath = "D:\TraceData\"

## Minimum free drive space in GB, that triggers stop
$MinFreeSpace = 10

## Name of pincipal session tracking cookie used by monitored site. If cookie cannot be matched then we'll add "No match" to monitor log 
$SCookieName = "SRCHUID"

## Enable network trace capturing only first 512 bytes of each packet
$netTrace = $false

## Display name of internal interface. Exactly as shown in ncpa.cpl, or will not trace!
$LanInterface = "LAN"

## Custom triggers that will stop trace and monitoring
$ResponseCodeTrigger = 503,504   ## Will trigger Setting this to 503 Service Unavailable and 504 GW Timeout 
$ResponseLengthTrigger = 0   ## Response content length in bytes

## Number of network trace files we'll retain before killing off the oldest. Only used if ne trace is in rollover mode, otherwise ignore.
$ETL = 12

## Enable process minidumps - Only useful if tracing locally on web server itself.
$DumProcs = $false

## Processes to dump on web server - Only useful if tracing locally on web server itself.
$Process = @("service_1", "service_2", "service_3")

## Number of times we want to dump each above proc
$nDump = 2

## Export server event logs (Application, System, Security) - Only useful if tracing locally on web server itself.
$EVTExport = $false
$EVTLog = @("Application", "System")

## Attempt to restart the following services after failure and data has been collected - Only useful if tracing locally on web server itself.
$TryRestoreService = $false
$svcName = @("Service name as displayed in services.msc")

## Send mail alerts. Only set to true if account and other mail transport details are correct
$SendAlert = $false
$EmailFrom = "user@live.co.uk"
$EmailTo = "user@live.co.uk"
$SMTPServer = "smtp-mail.outlook.com"
$SMTPuname = "user@live.co.uk"
$SMTPpw = "password"

## Other params that can be incorporated if necessary
$userAgent = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"



#############################  ATTEMPT TO RE-LAUNCH ELEVATED  ##################################

# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
# Check to see if we are currently running "as Administrator"
if ($myWindowsPrincipal.IsInRole($adminRole))
   {
   # We are running "as Administrator" - so change the title and background color to indicate this
   $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
   $Host.UI.RawUI.BackgroundColor = "DarkBlue"
   clear-host
   }
else
   {
   # Not running as Admin - so will try to re-launch with elevation
   
   # Create a new process object that starts PowerShell
   $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
   
   # Specify the current script path and name as a parameter
   $newProcess.Arguments = $myInvocation.MyCommand.Definition;
   
   # Indicate that the process should be elevated
   $newProcess.Verb = "runas";
   
   # Start the new process
   [System.Diagnostics.Process]::Start($newProcess);
   
   # Exit from the current un-elevated process
   exit
   }

#################################################################################################

####################################  LOGGING  ###################################################
# Make sure specified drive exists
if (Test-Path ($DataDrive = ($DataPath[0]+":"))) {
}
else {
	[Environment]::NewLine
	[Environment]::NewLine
	write-host "Specified trace volume does not appear to be available. Please check this before running the monitoring !" -ForegroundColor yellow
	[Environment]::NewLine
	[Environment]::NewLine
   exit
   }

$splitURI = ([System.Uri]$uri).Host.split('/')[-2..-1] -join '.'
if(!(Test-Path ($DataPath + $splitURI))) {
$DataPath = New-Item ($DataPath + $splitURI) -ItemType Directory -Force
$DataPath = ($DataPath.FullName + "\")
}
else {
$DataPath = ($DataPath + $splitURI + "\")
}

function log($string, $color)
{
       if ($Color -eq $null) {$color = "white"}
       write-host $string -foregroundcolor $color
            $string | out-file -Filepath ($DataPath + "OPsLog.txt") -append
    }
#############################  ATTEMPT TO RE-LAUNCH ELEVATED  ###################################

####################################  PROCESS DUMP  #############################################
function Procdump
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [System.Diagnostics.Process]
        $Process,
 
        [Parameter(Position = 1)]
        [ValidateScript({ Test-Path $_ })]
        [String]
        $DumpFilePath = $PWD
    )
 
    BEGIN
    {
        $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
        $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
        $Flags = [Reflection.BindingFlags] 'NonPublic, Static'
        $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
        $MiniDumpWithFullMemory = [UInt32] 2
    }
 
    PROCESS
    {
        $ProcessId = $Process.Id
        $ProcessName = $Process.Name
        $ProcessHandle = $Process.Handle
        $ProcessFileName = "$($ProcessName)_$($ProcessId)_$counter"

        $ProcessDumpPath = Join-Path $DumpFilePath $ProcessFileName
 
        $FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create)
 
        $Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle,
                                                     $ProcessId,
                                                     $FileStream.SafeFileHandle,
                                                     $MiniDumpWithFullMemory,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))
        
        $FileStream.Close()
        $n ++

        if (-not $Result)
        {
            $Exception = New-Object ComponentModel.Win32Exception
            $ExceptionMessage = "$($Exception.Message) ($($ProcessName):$($ProcessId))"
 
            # Remove any partially written dump files. For example, a partial dump will be written
            # in the case when 32-bit PowerShell tries to dump a 64-bit process.
            Remove-Item $ProcessDumpPath -ErrorAction SilentlyContinue
 
            throw $ExceptionMessage
        }
        else
        {
            Get-ChildItem $ProcessDumpPath
        }
    }
 
    END {}
    }
#################################################################################################


#####################################  RESTART SERVICE(s)  ######################################
Function Bounce-Services {
foreach ($svcName in $svcName) 
{
[Environment]::NewLine
Log "Entering service restart operation..."
try {
# Get dependent services
$depSvcs = Get-Service -name $svcName -dependentservices | Where-Object {$_.Status -eq "Running"} |Select -Property Name
 
# Check to see if dependent services are started
if ($depSvc -ne $null) {
      # Stop dependencies
      foreach ($depSvc in $depSvcs)
      {
            Stop-Service $depSvc.Name
            do
            {
                  $service = Get-Service -name $depSvc.Name | Select -Property Status
                  Start-Sleep -seconds 1
            }
            until ($service.Status -eq "Stopped")
      }
}
# Restart service
Log "Restarting service: $svcName. Please wait..."
Restart-Service $svcName -force
do
{
      $service = Get-Service -name $svcName | Select -Property Status
      Start-Sleep -seconds 1
}
until ($service.Status -eq "Running") 
$depSvcs = Get-Service -name $svcName -dependentservices |Select -Property Name
# We check for Auto start flag on dependent services and start them even if they were stopped before
foreach ($depSvc in $depSvcs)
{
      $startMode = gwmi win32_service -filter "NAME = '$($depSvc.Name)'" | Select -Property StartMode
      if ($startMode.StartMode -eq "Auto") {
            Start-Service $depSvc.Name
            do
            {
                  $service = Get-Service -name $depSvc.Name | Select -Property Status
                  Start-Sleep -seconds 1
            }
            until ($service.Status -eq "Running")
      }
}
} 
catch {
[Environment]::NewLine
write-host "A timeout occured whilst attempting to restart the $svcName, service. Please try manualy..." -ForegroundColor yellow -NoNewline
Break;
}
}
}
#################################################################################################


#####################################  SEND MAIL  ###############################################
$MailFunc = { Function Send-mail ($AlertSubject,$AlertBody) {
                     try {

                            $body = ""
                            $EmailSubject = (" Website monitoring from computer " + $env:computername + ": " + $AlertSubject) 
                            $mailmessage = New-Object system.net.mail.mailmessage  
                            $mailmessage.from = ($EmailFrom)  
                            $mailmessage.To.add($EmailTo) 
                            $mailmessage.Subject = $EmailSubject
                            $mailmessage.Body = $AlertBody
                            $mailmessage.IsBodyHTML = $true 
                            $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer,587)   
                            $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($SMTPuname, $SMTPpw);  
                            $SMTPClient.EnableSsl = $true  
                            $SMTPClient.Send($mailmessage) 
                            }
                        Catch {
                            [Environment]::NewLine
                            Write-Warning "$($Error[0])"
                            }
                }          
    }         
#################################################################################################


#######################################  STOP  ##################################################
function STOP {
Param ([string]$Outputreport)
"STOP called..." | out-file -Filepath ($DataPath + "OPsLog.txt") -append
if ($netTrace) {
    cls
    [Environment]::NewLine
    Log "Calling net trace STOP..." yellow
    [Environment]::NewLine
    netsh trace stop 
    }
if ($DumProcs) {
    cls
    [Environment]::NewLine
    Log " Dumping processes..."
    foreach ($Process in $Process) 
        {
        for($counter = 1; $counter -le $nDump; $counter++)
	         {
	            Get-Process $Process | Procdump -DumpFilePath $DataPath
	         }
    }
}

## Use following  block to write and execute batch file when calling start trace operation
#$batCon = @'
#"Do SOME STUFF IN BATCH FILE
#'@
#[System.IO.File]::WriteAllLines("$env:TEMP\CTrace.bat", $batCon) # Using this approach to avoid DOM encoding
#$A = saps -FilePath "$env:TEMP\CTrace.bat" -Wait -WindowStyle Hidden

## Export event logs
if ($EVTExport) {
    cls
    [Environment]::NewLine
    Log "Exporting server logs..."
        foreach ($EVTLog in $EVTLog) 
    {
    $exportFileName = $EVTLog + (get-date -f yyyyMMdd) + ".evt"
    $logFile = Get-WmiObject Win32_NTEventlogFile | Where-Object {$_.logfilename -eq $EVTLog}
    $logFile.backupeventlog($DataPath + $exportFileName)
    }
}
## Restart service(s) to try and restore service
If ($TryRestoreService) {
Log "Calling service restart..."
    cls
    Bounce-services
    }
## Send mail STOP monitor notification if mail alerts enabled
     if ($SendAlert) { 
         Start-Job -name STOPMailer -ScriptBlock { param($AlertSubject,$AlertBody,$EmailFrom,$EmailTo,$SMTPServer,$SMTPuname,$SMTPpw,$uri)
         Send-Mail (" STOPPED")(" Monitoring of target site: " + $uri + " has stopped from computer: " + $env:computername)
         "Send mail - Tracing stopped" | out-file -Filepath ($DataPath + "OPsLog.txt") -append
         } -ArgumentList $AlertSubject,$AlertBody,$EmailFrom,$EmailTo,$SMTPServer,$SMTPuname,$SMTPpw,$uri -InitializationScript $MailFunc | Out-Null
                 }
         #get-job | Receive-Job
         #Remove-Job -Name Mailer -force -ea silentlycontinue
cls
[Environment]::NewLine
[Environment]::NewLine
Write-host "Monitoring stopped. View the .htm monitor log for failed request info and also the trace .etl file with Netmon..." -ForegroundColor Green
[Environment]::NewLine
[Environment]::NewLine
"Waiting for STOPMAILER job to complete" | out-file -Filepath ($DataPath + "OPsLog.txt") -append
Wait-Job -Name STOPMailer -ea SilentlyContinue | Out-Null
"Waiting for MONITOR job to complete" | out-file -Filepath ($DataPath + "OPsLog.txt") -append
Wait-Job -Name STOPMailer -ea SilentlyContinue | Out-Null
"Remove all running jobs" | out-file -Filepath ($DataPath + "OPsLog.txt") -append
Remove-Job * -force -ea silentlycontinue | out-null
"Exiting script..." | out-file -Filepath ($DataPath + "OPsLog.txt") -append
## Display logged stats in browser
$Outputreport | out-file $StatFile -Append
"Display monitor log in browser" | out-file -Filepath ($DataPath + "OPsLog.txt") -append
Invoke-Expression $StatFile
Break;
}
#################################################################################################
  

#####################################  INITIALIZE ###############################################
[console]::SetWindowSize(140,18)
cls
[Environment]::NewLine
"Remove all exisiting jobs..." | out-file -Filepath ($DataPath + "OPsLog.txt") -append
Remove-Job * -force -ea silentlycontinue
# Time out for initial site availability check in seconds
$InitTimeOut = 12
$StatFile = "$DataPath{0:dd.MM.yy}.htm" -f (Get-Date) 

"ISE env check as does not support CTRL+C" | out-file -Filepath ($DataPath + "OPsLog.txt") -append 
try{
   [console]::TreatControlCAsInput = $false
   } 
   Catch {
   (new-object -ComObject wscript.shell).Popup("Script cannot be run in ISE. Please relaunch from a PS cmd line",0,"",0x10)
   exit
   }

if ($AADPreAuthN) {
$SCookieName = "AzureAppProxyAccessCookie"
}

## Quick check to make sure site is avalaible before initialising
Log " Verifying site availability before starting..." yellow
sleep 2
    try{
                            if ($IgnoreTLS) {
                                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                                }
                            [net.httpWebRequest] $req = [net.webRequest]::create($uri)
                            $req.UserAgent = $userAgent
                            $req.TimeOut = (new-timespan -seconds $TimeOut).TotalMilliseconds
                            $req.CookieContainer = New-Object System.Net.CookieContainer

                            # Set some reasonable limits on resources used by this request, if necessary
                            $req.MaximumAutomaticRedirections = 4
                            #$req.MaximumResponseHeadersLength = 4

                            # Set credentials to use for this request.
                            #$req.Credentials = CredentialCache.DefaultCredentials;
                            #HttpWebResponse response = (HttpWebResponse)$req.GetResponse

                            [net.httpWebResponse] $res = $req.getResponse()
                            $resst = $res.getResponseStream()
                            $sr = new-object IO.StreamReader($resst)
                            $result = $sr.ReadToEnd()


                            $StatusCode = ($req.GetResponse().Statuscode) -as [int]
                            $CLength = ($req.GetResponse().ContentLength) -as [int]
                            $SCodeDescription = ($req.GetResponse().Statuscode) -as [string]
                            (" Status code = " + $StatusCode) | out-file -Filepath ($DataPath + "OPsLog.txt") -append 
                            (" Status Description = " + $SCodeDescription) | out-file -Filepath ($DataPath + "OPsLog.txt") -append 
                            (" Content length = " + $result.Length) | out-file -Filepath ($DataPath + "OPsLog.txt") -append 
                            #$res.close()

        }
    catch {
            cls
            [Environment]::NewLine
            Log " Target site unavailable so tracing cancelled due to:" yellow
            [Environment]::NewLine
            $errorstring = "$($error[0])"
            $StatusCode = ([regex]::Match($errorstring,"\b\d{3}\b")).value
            Log (" Error: " + $errorstring + " !") Red
            [Environment]::NewLine
			Log " Verify site availability through browser, and re-run script to start again..." yellow
            [Environment]::NewLine
			#Stop-transcript | out-null
            break
		}

cls
1..3 | % -begin {[Environment]::NewLine} -process {(Log " Starting continous tracing and monitoring..." yellow);sleep 1;sleep 1}

## Clean up an previous net trace etl file and bgin tracing if enabled
try {
Remove-Item "$DataPath*.etl" | Where { ! $_.PSIsContainer }

## Use following  block to write and execute batch file when calling stop trace operation
#$batCon = ('
#@echo off
#"DO SOME STUFF IN BATCH
#')
#[System.IO.File]::WriteAllLines("$env:TEMP\CTrace.bat", $batCon) # Using this approach to avoid UTF16 DOM encoding
#$A = saps -FilePath "$env:TEMP\CTrace.bat" -Wait -WindowStyle Hidden

if ($netTrace) {
    $netCon = ('
    @echo off
    netsh trace start scenario=netconnection capture=yes CaptureInterface="') + $LAnInterface + ('" level=4 filemode=circular overwrite=yes packettruncatebytes=512 maxsize=400 traceFile=') + $DataPath + ('NetTrace.etl report=no')
    [System.IO.File]::WriteAllLines("$env:TEMP\netTrace.bat", $netCon) # Using this approach to avoid UTF16 DOM encoding
    $B = saps -FilePath "$env:TEMP\netTrace.bat" -Wait -WindowStyle Hidden
 }
if ( $(Try { Test-Path $StatFile.trim() } Catch { $false }) ) {
     Remove-Item $StatFile
     #$Outputreport = "<BR><BR>"
     #$Outputreport | out-file $StatFile -Append
 }
Else {
     ## Create monitor log if not already present
     New-Item -ErrorAction Ignore -ItemType directory -Path $DataPath
 }
     $Outputreport = "<HTML><HEAD><TITLE>Web Site Monitoring Report</TITLE></HEAD><BODY background-color:peachpuff><BR><Table width=100% border=1 cellpadding=30 cellspacing=0><TD><font size=""6"" color =""#4d4d4d"" face=""Microsoft Tai le""><b>Monitoring Report For Web Site:</b></font><font size=""4"" color=""#99000"" face=""Microsoft Tai le"">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; $uri</font></TABLE>"
     $Outputreport += "<BR><Table width=100% border=1 cellpadding=0 cellspacing=0>"
     $Outputreport | out-file $StatFile
     
     ## Send mail START monitor notification if mail alerts enabled
     if ($SendAlert) { 
         Start-Job -name STARTMailer -ScriptBlock { param($AlertSubject,$AlertBody,$EmailFrom,$EmailTo,$SMTPServer,$SMTPuname,$SMTPpw,$uri)
         Send-Mail (" STARTED...")(" Monitoring of target site: " + $uri + " has begun, from computer: " + $env:computername)
         } -ArgumentList $AlertSubject,$AlertBody,$EmailFrom,$EmailTo,$SMTPServer,$SMTPuname,$SMTPpw,$uri -InitializationScript $MailFunc | Out-Null
                 }
         #get-job | Receive-Job
         #Remove-Job -Name Mailer -force -ea silentlycontinue
 }
Catch {
      Log "$($Error[0])" Red
      }

#################################################################################################

##############################  Monitoring  #####################################################
while ($true) {
sleep 1

    ##  Trap Ctrl+C so we can kill the lot
   [console]::TreatControlCAsInput = $true   ## WHY DOES THIS KEEP REVERTING TO FALSE !!!! `
   if ($Host.UI.RawUI.KeyAvailable -and (3 -eq [int]$Host.UI.RawUI.ReadKey("AllowCtrlC,IncludeKeyUp,NoEcho").Character))
   {
      cls
      [Environment]::NewLine
      [Environment]::NewLine
      write-host "                                                                                                                                          " -Background DarkRed
      write-host "                                                                                                                                          " -Background DarkRed
      write-host "                                                                                                                                          " -Background DarkRed
      write-host "                               Ctrl-C detected so stopping trace and collecting data. Don't try to stop me...                             " -Background DarkRed
      write-host "                                                                                                                                          " -Background DarkRed
      write-host "                                                                                                                                          " -Background DarkRed
      write-host "                                                                                                                                          " -Background DarkRed -NoNewline
      STOP "</Table><Table><TR><TD><font face=""Microsoft Tai le""><BR>Last stop triggered by user</font></TD></TR></Table></BODY></HTML>"
   }

#check for monitor running
if((Get-Job Monitor -ChildJobState "Running" -ErrorAction SilentlyContinue | Measure-Object).count -lt 1) {
Start-Job -name Monitor -ScriptBlock { param($AlertSubject,$AlertBody,$SendAlert,$EmailFrom,$EmailTo,$SMTPServer,$SMTPuname,$SMTPpw,$uri,$IgnoreTLS,$Interval,$TimeOut,$DataPath,$MinFreeSpace,$SCookieName,$ETL,$Process,$nDump,$netTrace,$LanInterface,$ResponseCodeTrigger,$ResponseLengthTrigger,$RestoreService,$StatFile,$DataDrive,$userAgent)
$triggered = $false
while($true) { 
                cls
                [Environment]::NewLine
                write-host " Trace and monitoring running..." -ForegroundColor Green
                [Environment]::NewLine
                write-host (" Endpoint:             " + $uri)
                ## Drive space query
                $FreeSpace = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$DataDrive'" | ForEach-Object {[math]::truncate($_.freespace / 1GB)}
                $time = try{
                            
                            $request = $null 
                            if ($IgnoreTLS) {
                                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                                } 
                            ## Request the URI, and measure how long the response took.
                            $result1 = Measure-Command { [net.httpWebRequest] $req = [net.webRequest]::create($uri) } 
                            $result1.TotalMilliseconds 
                                                        
                            $req.UserAgent = $userAgent
                            $req.TimeOut = (new-timespan -seconds $TimeOut).TotalMilliseconds
                            $cc = New-Object System.Net.CookieContainer
                            $req.CookieContainer = $cc

                            # Set some reasonable limits on resources used by this request, if necessary
                            $req.MaximumAutomaticRedirections = 4
                            $req.MaximumResponseHeadersLength = 4

                            [net.httpWebResponse] $res = $req.getResponse()
                            $resst = $res.getResponseStream()
                            $sr = new-object IO.StreamReader($resst)
                            $result = $sr.ReadToEnd()

                            #Write-Host $result
                            $StatusCode = ($req.GetResponse().Statuscode) -as [int]
                            $CLength = $result.Length
                            $SCodeDescription = ($req.GetResponse().Statuscode) -as [string]
							
							$cc.GetCookies($req.RequestUri) | % { if ($_.Name -contains $SCookieName) { $SCookie = $_.Name + $_.Value } }
							Try {
								if (![string]::IsNullOrEmpty($SCookie)) {
									if ($SCookie.length > 79) { 
									$SCookie = $SCookie.substring(0,80)
									}
								}
								else {
								$SCookie = "No Match"
								}
							}
							catch {
							}

                            Write-Host " Last response:       "$StatusCode -ForegroundColor white
                            Write-Host " Status Description:  "$SCodeDescription -ForegroundColor white
                            Write-Host " Content length:      "$CLength -ForegroundColor white
                            Write-Host " Site Session Cookie: "$SCookie -ForegroundColor white -NoNewline

                            }
                        catch {

                               #Write-Host $errorstring
                               $errorstring = "$($error[0])"
                               $StatusCode = ([regex]::Match($errorstring,"\b\d{3}\b")).value

                               #Write-Host " TEMP:       " $cc.GetCookies($req.RequestUri) | % { if ($_.Name -contains $SCookieName) { $SCookie = $_.Value } }
                               #Write-Host "Press any key to continue ..."
                               #$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                               
                               Write-Host " Last response:        Not available" -ForegroundColor white
                               Write-Host " Status Description:   Not available" -ForegroundColor white 
                               Write-Host " Content length:       Not available" -ForegroundColor white
                               Write-Host " Site Session Cookie:  Not available" -ForegroundColor white
                               } 
                
                [Environment]::NewLine
                Write-Host " Query interval every $Interval seconds" -ForegroundColor white
                [Environment]::NewLine
                Write-Host " Press Ctrl-C to terminate, but do not close window..." -ForegroundColor Green -NoNewline
                $res.close()
                Sleep -s $Interval

           if($result -ne $null)
            {
                $Outputreport = "<TR bgcolor=#b3e0ff align=center><TD><pre>  #   </pre></TD><TD><pre>  Time  </pre></TD><TD><pre>  Status  </pre></TD><TD><pre>  Desc  </pre></TD><TD><pre>  ResponseLength  </pre></TD><TD><pre>  TimeTaken  </pre></TD><TD><pre>  Session Cookie  </pre></TD><TD><pre>  Free space on $($DataDrive)  </pre></TD></TR>"
                Foreach($Entry in $Result)
                {
                    if($StatusCode -eq 500)
                    {
                        $Outputreport += "<TR bgcolor=yellow>"
                        if ($SendAlert) {
                            Send-mail (" PROBLEM DETECTED!!")(" A 500 'Internal Error response was received by computer " + $env:computername: + ", from target site " + $uri + " !!")
                            $Triggered = $true
                            }
                    }
                    elseif($CLength -lt 1)
                    {
                        $Outputreport += "<TR bgcolor=yellow>"
                        if ($SendAlert) {
                            Send-mail (" POSSIBLE PROBLEM DETECTED!!")(" A zero length content response was received by computer " + $env:computername: + ", from target site " + $uri + " !!")
                            $Triggered = $true
                            }
                    }
                    elseif($StatusCode -eq 503)
                    {
                        $Outputreport += "<TR bgcolor=#ff6666>"
                        if ($SendAlert) {
                            Send-mail (" PROBLEM DETECTED!!")(" A 503 'Service Unavailable response was received by computer " + $env:computername: + ", from target site " + $uri + " !!")
                            $Triggered = $true
                            }
                    }
                    elseif($StatusCode -eq 504)
                    {
                        $Outputreport += "<TR bgcolor=#ff6666>"
                        if ($SendAlert) {
                            Send-mail (" PROBLEM DETECTED!!")(" A 504 'Gateway timeout response was seen by computer " + $env:computername: + ", whilst monitoring target site " + $uri + " !!")
                            $Triggered = $true
                            }
                    }
                    else
                    {
                        $Outputreport += "<TR>"
                        if ($SendAlert) {
                            if ($Triggered -eq $true) {
                            Send-mail (" SERVICE RESTORED...")(" Target site " + $uri + " appears to be available again, from computer: " + $env:computername:)
                            $triggered = $false
                                }
                            }
                    }
                    
					# Size cookie to column
					if ($SCookie.length > 31) {
					$SCookie = $SCookie.substring(0,100)
					}
					
					$Outputreport += "<TD align=center><pre> $($count ; $count ++)  </pre></TD><TD align=center><pre> $(Get-Date) </pre></TD><TD align=center><pre> $($StatusCode) </pre></TD><TD align=center><pre> $($SCodeDescription) </pre></TD><TD align=center><pre> $($CLength) </pre></TD><TD align=center><pre> $($time) </pre></TD><TD align=center><pre> $($SCookie) </pre></TD><TD align=center><pre> $($FreeSpace) </pre></TD></TR>"
                }
                #$Outputreport += ""
                $Outputreport | out-file $StatFile -Append
            }
            else
            {
                $Outputreport = "<TR bgcolor=#b3e0ff align=center><TD><pre>  #   </pre></TD><TD><pre>  Time  </pre></TD><TD><pre>  Status  </pre></TD><TD><pre>  Desc  </pre></TD><TD><pre>  ResponseLength  </pre></TD><TD><pre>  TimeTaken  </pre></TD><TD><pre>  Cookie  </pre></TD><TD><pre>  Free space on $($DataDrive)  </pre></TD></TR>"
                $Outputreport += "<TR bgcolor=#ff6666>"
                $Outputreport += "<TD align=center><pre> $($count ; $count ++)  </pre></TD><TD align=center><pre> $(Get-Date) </pre></TD><TD align=center><pre> - </pre></TD><TD align=center><pre> Site unavailable </pre></TD><TD align=center><pre> 0 </pre></TD><TD align=center><pre> - </pre></TD><TD align=center><pre> - </pre></TD><TD align=center><pre> $($FreeSpace) </pre></TD></TR>"
                $Outputreport | out-file $StatFile -Append
                if ($SendAlert) {
                    Send-mail (" PROBLEM DETECTED!!")(" Connectivity issues have been detected whilst connecting to target site " + $uri + " from computer: " + $env:computername: + " !!")
                    $Triggered = $true
                    }
                }
                #$Outputreport += ""
           
            ## If enabled, monitor total amount of network trace files and remove oldest
            $items = Get-ChildItem $DataPath*.etl
            if ($items.count -gt $ETL) {
                    $items | Sort-Object { [regex]::Replace($_, '\d+',{$args[0].Value.Padleft(20)})} | Select-Object -First ($items.count - $ETL) | Foreach-Object { Remove-Item $_ -ErrorAction SilentlyContinue }
                    }
            ## Trigger - Not including 500 as the odd one may stop trace prematurely
            if ($StopOnFailure) {
            if ($StatusCode -eq $ResponseCodeTrigger -or $CLength -eq $ResponseLengthTrigger ) { 
            [Environment]::NewLine
            Write-Host "Site shows signs of a problem. Collecting dumps and exiting..." -Background DarkRed -NoNewline
            $Outputreport = "<Table><TR><TD><font face=""Microsoft Tai le""><BR>Last stop triggered by problem with response from site</font></TD></TR></Table></BODY></HTML>"
            $Outputreport | out-file $StatFile -Append
            Sleep 6
            eXIT
            }
            }
            ## Trigger - Monitor drive space and kill trace if drive space is exhausted
            if ($FreeSpace -lt $MinFreeSpace) { 
            [Environment]::NewLine
            Write-Host "Drive space super low so terminating trace..." -Background DarkRed -NoNewline
            $Outputreport = "<Table><TR><TD><font face=""Microsoft Tai le""><BR>Last run stopped due to free drive space having dropped below minimum size of: $($MinFreeSpace) </font></TD></TR></Table></BODY></HTML>"
            $Outputreport | out-file $StatFile -Append
            Sleep 6
            eXIT
            }

            $Result = @()

            }
            } -ArgumentList $AlertSubject,$AlertBody,$SendAlert,$EmailFrom,$EmailTo,$SMTPServer,$SMTPuname,$SMTPpw,$uri,$IgnoreTLS,$Interval,$TimeOut,$DataPath,$MinFreeSpace,$SCookieName,$ETL,$Process,$nDump,$netTrace,$LanInterface,$ResponseCodeTrigger,$ResponseLengthTrigger,$RestoreService,$StatFile,$DataDrive,$userAgent -InitializationScript $MailFunc | Out-Null
             }
    get-job | Receive-Job
    if (@(Get-Job | Where { $_.State -eq "Running" }).Count -eq 0) {
    STOP
    }
}
