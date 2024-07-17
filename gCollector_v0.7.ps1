
Write-Output "======================" 
Write-Output "======================" 
Write-Output "   twitter:@galkofahi" 
Write-Output "   gCollector_v0.4"
Write-Output "======================"
Write-Output "======================"
 
Write-Output "    		==============================" 
Write-Output "           	  The Beginingg of Results              "
Write-Output "			=============================="
Write-Output "`n"
Write-Output "====================="
Write-Output "===== System Information ====" 
Write-Output "====================="
Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property CSName, Caption, Version, BuildNumber, OSArchitecture
Write-Output "`n"
Write-Output "====================="
Write-Output "==== BIOS Information ====" 
Write-Output "====================="
Get-WmiObject -Class Win32_BIOS | Select-Object -Property Manufacturer, Name, Version, SerialNumber
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Computer System Information ===="  
Write-Output "====================="
Get-WmiObject -Class Win32_ComputerSystem | Select-Object -Property Name, Manufacturer, Model, NumberOfProcessors, SystemType
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Logged-On Users ===="   
Write-Output "====================="
Get-WmiObject -Class Win32_LoggedOnUser | Select-Object -Property Antecedent, Dependent
Write-Output "`n"
Write-Output "====================="
Write-Output "==== User Account Information ====" 
Write-Output "====================="
Get-WmiObject -Class Win32_UserAccount | Select-Object -Property Name, Domain, SID, Status > User_Account_Information.txt
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Running Processes ===="
Write-Output "====================="
Get-WmiObject -Class Win32_Process | Select-Object -Property Name, ProcessId, CommandLine > Running_Process.txt
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Services ====" 
Write-Output "====================="
Get-WmiObject -Class Win32_Service | Select-Object -Property Name, DisplayName, State, StartMode, PathName > Services.txt
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Network Adapter Configuration ====" 
Write-Output "====================="
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object -Property Description, MACAddress, IPAddress
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Scheduled Tasks ====" 
Write-Output "====================="
Get-WmiObject -Namespace "root\cimv2" -Class Win32_ScheduledJob | Select-Object -Property JobId, JobStatus, Name
Write-Output "`n"
Write-Output "====================="
Write-Output "==== WMI Event Filters ====" 
Write-Output "====================="
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Select-Object -Property Name, Query, EventNamespace
Write-Output "`n"
Write-Output "====================="
Write-Output "==== WMI Event Consumers ====" 
Write-Output "====================="
Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer | Select-Object -Property Name, CommandLineTemplate 
Write-Output "`n"
Write-Output "====================="
Write-Output "==== WMI Filter to Consumer ===="
Write-Output "====================="
Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Select-Object -Property Filter, Consumer
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Antivirus Product Information ===="
Write-Output "====================="
Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct | Select-Object -Property displayName, productState
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Disk Information ===="
Write-Output "====================="
Get-WmiObject -Class Win32_DiskDrive | Select-Object -Property Model, Manufacturer, InterfaceType, MediaType
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Logical Disk Information ====" 
Write-Output "====================="
Get-WmiObject -Class Win32_LogicalDisk | Select-Object -Property DeviceID, DriveType, FileSystem, FreeSpace, Size
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Event Logs ====" 
Write-Output "====================="
Get-EventLog -LogName System -Newest 10 > System_events.txt
Write-Output "`n"
Write-Output "======================" 
Get-EventLog -LogName Application -Newest 10 > Application_events.txt
Write-Output "`n"
Write-Output "======================" 
Get-EventLog -LogName Security -Newest 10 > Security_events.txt
Write-Output "`n"
Write-Output "====================="
Write-Output "==== Unusual Network Connections ====" 
Write-Output "====================="
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotPort, State
Write-Output "`n"
Write-Output "====================="
Write-Output "==== List Of Auto-Start Program ====" 
Write-Output "====================="
Write-Output "===== HKLM 1 ===="
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Write-Output "========= HKLM 2=========="
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\*'
Write-Output "=========HKCU 1=========="
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Write-Output "=========HKCU 2=========="
Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\*'

Write-Output "`n"

Write-Output "				======================" 
Write-Output "				     End of Results	      "						 
Write-Output "				======================" 