#USERASSIST    ---Finding out:
                        # What applications, files, links, and other objects that have been accessed {CEB}
                        # or Shortcuts {F4E} A targeted user used recently
 
 #CEBFF5CD: Executable File Execution
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
 #F4E57C4B: Shortcut File Execution
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count"

#Find out what Version of Windows You're Running
systeminfo


#BAM --- Background Activity Monitor --- 

#Every User on the System
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings\*
#Single User on the System
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings\<SID>

#In OLDER Verisions (18.03 and older) ***\state\ is gone from the adddress
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*

#RECYCLEBIN
#Find the Contents of the Recycle Bin
Get-Childitem 'C:\$RECYCLE.BIN' -Recurse -Verbose -Force | select FullName
    #For .txt files there will always be 2 files.txt.... they'll start with $I and a $R
        #   get-content of the $I file will give you the location it was deleted from
        #   get-content of the $R file will give you the actual contents of the file


   
#PREFETCH  --- Log of names of executables run in windows. Even if a person drops a file, runs it, then deletes it... it stays as an artifact in here
    # Windows 7 and older only captures 124, after that, it captures a lot
Get-Childitem -Path 'C:\Windows\Prefetch' -ErrorAction Continue | select -First 50
    Get-ChildItem -Path 'C:\Windows\Preftch' -ErrorAction Continue | findstr i chrome

    Get-ChildItem 'C:\$RECYCLE.BIN' -Recurse -Force | Where-Object {$_.FullName -like '*.txt*' -or (Get-Content $_.FullName -ErrorAction SilentlyContinue) -like '*.txt*'} | Get-Content
    Get-ChildItem 'C:\$RECYCLE.BIN' -Recurse -Force | Where-Object {$_.FullName -like '*DontTrashMeyo*' -or (Get-Content $_.FullName -ErrorAction SilentlyContinue) -like '*DontTrashMeyo*'} | Get-Content
    Get-ChildItem 'C:\$RECYCLE.BIN' -Recurse -Force | Where-Object {$_.FullName -like '*DontTrashMeyo*' -or (Get-Content $_.FullName -ErrorAction SilentlyContinue) -like '*DontTrashMeyo*'} | select FullName

   
#JUMP LISTS  --- And example of this is the windows key interface that pops up
#Programs/Items that were recently used
Get-Childitem -Recurse C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction silentlyContinue | select FullName, LastAccessTime
Get-Childitem -Recurse C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName, CreationTime |ft -wrap
Get-Childitem -Recurse C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName, LastAccessTime |ft -wrap
#or
Get-Childitem -Recurse $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName,LastAccessTime | ft -wrap



Get-Childitem -Recurse C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName, CreationTime |ft -wrap

#RECENT FILES
Get-childItem 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt'
Get-childItem 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.*'

#Converting a Single Value from Hex to Unicode
[System.Text.Encoding]::Unicode.GetString((gp "REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt")."1")


#Convert All Files
Get-Item "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" | select -Expand property | ForEach-Object {
    [System.Text.Encoding]::Default.GetString((Get-ItemProperty -Path "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" -Name $_).$_)
}

#BROWSER ARTIFACTS
# Frequency
strings.exe 'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\History' -accepteula

#install Sysinternals for remote use
net use * http://live.sysinternals.com


# For Edge, or FF, just change the address to \Local\....

strings.exe 'C:\users\student\AppData\Local\Google\Chrome\User Data\Default\History' -accepteula | select-object -unique
strings.exe 'C:\users\*\AppData\Local\Google\Chrome\User Data\Default\History | select-object -unique



# Most Visited
strings.exe 'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\Top Sites'
'

# User Names#
strings.exe  'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\Login Data'
strings.exe  'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\Login Data' | findstr -i "https*"

#Find FQDNs in Sqlite Text files
$History = (Get-Content 'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\History') -replace "[^a-zA-Z0-9\.\:\/]",""

$History | Select-String -Pattern "(https|http):\/\/[a-zA-Z_0-9]+\.\w+[\.]?\w+[\.]?\w+" -AllMatches|foreach {$_.Matches.Groups[0].Value}| ft


New-Item C:\Users\andy.dwyer\Desktop\auditing.txt
Set-Content C:\Users\andy.dwyer\Desktop\auditing.txt "this file is for auditing"
Get-Content C:\Users\andy.dwyer\Desktop\auditing.txt


##AUDITING
#get the GUI for reviewing logs.
# looking at Windows Logs > Security 
eventvwr


#AUDIT Policies
#View All Audit Options
auditpol /get /category:*
#View Subcategory
auditpol /get /category:"Object Access"
#Sets it
auditpol /set /subcategory:"File System"
#Clears It
auditpol /set /subcategory:"File System" /success:disable

#=====Command Prompt=====
#-=-=-= Windows Event Utility gives the most info =-=-=-
#EVENT LOGS
#Show all logs    ---- use wevtutil /? to see all the commands available
wevtutil el
#Get security log info
wevtutil gli security
#Get last 3 events from security log and view in human readable format.
wevtutil qe security /c:3 /f:text    

#=====End Command Prompt=====

#Last 10 entries in System Log
Get-EventLog -LogName System -Newest 10
Get-EventLog -LogName System -Newest 10 | Format-Table -wrap
Get-EventLog -LogName System | Format-Table -wrap

#Search the event logs and show the entire message
Get-Eventlog -LogName Security | ft -wrap
#Search for a String
Get-Eventlog -LogName Security | ft -wrap | findstr /i $tR1nG
Get-Eventlog -LogName Security | ft -wrap | findstr /i "An attempt was made to access an object."


#Finding Log Type to Query
Get-WinEvent -Listlog *

#Checking If a User Logged on
Get-Winevent -FilterHashtable @{logname='Security';id='4624'} | ft -Wrap
Get-Winevent -FilterHashtable @{logname='Security';id='4624'} | ft -Wrap | findstr /i "generated"
    # to see the different types of security IDs, Use the link (https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/Default.aspx)

#Checking Powershell Operational Logs
Get-WinEvent Microsoft-Windows-PowerShell/Operational |Where-Object {$_.Message -ilike "*Out-Default*"} | Format-List

Get-WinEvent Microsoft-Windows-PowerShell/Operational |Where-Object {$_.Message -ilike "*Pipeline ID = 4103"} | Format-List