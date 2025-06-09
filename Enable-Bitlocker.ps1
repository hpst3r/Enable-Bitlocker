#Requires -RunAsAdministrator
<#
.SYNOPSIS
Enables BitLocker encryption on fixed volumes residing on SSD media when the machine has a TPM active.

.INPUTS
[bool]$CheckMediaType = $true
  True: Encrypt only disks with Win32_LogicalDisk MediaType reporting Fixed (3).
  False: Encrypt everything regardless of media type (fixed or removable).
  $true excludes things like USB drives or SD cards, which is typically desirable.

[bool]$EncryptSpinningDrives = $false
  $true: Encrypt spinning hard drives as well as SSDs (as reported by Get-PhysicalDisk).
  $false: Only encrypt solid state drives (SSDs). Do not encrypt spinning hard disks.

[bool]$LogToFile = $false
  $true: Log the script's output to a file with Write-Transcript.
  $false: Do not log the script's output to a file.

[string]$LogFilePath = (Join-Path -Path $env:TEMP -ChildPath "bitlocker-$(Get-Date -UFormat %s)")
  The destination to write a transcript of the script to. Only does something if $LogToFile -eq $true.

.NOTES
BitLocker drive encryption enablement and verification script
Enables BitLocker drive encryption forcibly on fixed SSD volumes with TPM and/or recovery key protectors.
Decrypts and re-encrypts encrypted volumes that lack protection.
Verifies key protectors on volumes that are already encrypted and protected.
If applicable, backs up BitLocker recovery key to Active Directory (stored as a child of the relevant Computer object) or Entra ID.
Intended to fail gracefully and skip trying to encrypt unknown volumes rather than terminating the script.

Highly recommended to delegate access to BitLocker key management to a service account that will run this script, or use the Computer account (do not use a Domain Admin).
See: https://learn.microsoft.com/en-us/archive/blogs/craigf/delegating-access-in-ad-to-bitlocker-recovery-information

PowerShell versions: Windows 5.1 & Core 7
Tested on: Windows 11 Pro 23H2, Windows 11 Pro 24H2, Windows 11 Enterprise LTSC 2024
Requires: elevated local account OR elevated account with permission to modify BitLocker recovery information in AD (if key backup is desired)

.DESCRIPTION
REQUIRES System or Local Administrator privileges to function.

Checks for presence of a TPM. If a TPM is found, we want to encrypt disks.

Iterates through volumes that can be encrypted.

Confirms that PhysicalDisk which is hosting a LogicalDisk which is hosting a Partition is an SSD (if not $EncryptSpinningDrives).
Confirms that Win32_LogicalDisk which is hosting a Partition with MountPoint (drive letter) is of type 3, fixed (if $CheckMediaType).
Checks for a relatively common edge case with disk encrypted but protection off. Decrypts disk then re-enables protection.
Confirms that, if BitLocker is enabled, it has a TPM and recovery key protector, and makes it so only those two protectors are active.

If the computer is domain joined, attempts to sync the recovery key to Active Directory. This is possible with the System account.
If the computer is Entra joined, attempts to back up the recovery key to Entra.
If the computer is not joined to an identity service, the recovery key WILL NOT BE BACKED UP. Exercise caution!
#>
param (
  [Parameter()]
  [bool]$CheckMediaType = $true,
  [Parameter()]
  [bool]$EncryptSpinningDrives = $false,
  [Parameter()]
  [bool]$LogToFile = $false,
  [Parameter()]
  [string]$LogFilePath = (Join-Path -Path $env:TEMP -ChildPath "bitlocker-$(Get-Date -UFormat %s)")
)
BEGIN {

  if ($LogToFile) {
    Start-Transcript `
      -Path $LogFilePath
  }

  [int]$EncryptionFailures = 0

  function Sync-KeyProtectors {
    param (
      [System.Collections.ArrayList]$DesiredProtectors = @("Tpm", "RecoveryPassword"),
      [array]$BitLockerVolumes = (Get-BitLockerVolume),
      [bool]$Remove = $true,
      [bool]$RemoveTpm = $false
    )

    :Partition foreach ($Volume in ($BitLockerVolumes)) {
      [int]$Match = 0
      [int]$DesiredMatch = $DesiredProtectors.Count # save this here since I'll be removing objects

      if ($Volume.KeyProtector -contains("ExternalKey")) {
        $DesiredMatch += 1
      }

      :KeyProtector foreach ($KeyProtector in $Volume.KeyProtector) {

        if ($DesiredProtectors.Contains([string]$KeyProtector.KeyProtectorType)) {
          Write-Host -Object `
            "Sync-KeyProtectors: Info: $($KeyProtector) was detected on volume $($Volume.MountPoint) and was requested."

          $DesiredProtectors.Remove([string]$KeyProtector.KeyProtectorType)

          $Match++
        } # if DesiredProtectors contains KeyProtector
        elseif ($Remove) {
          if (($Volume.VolumeType -eq "Data") -and ($KeyProtector.KeyProtectorType -eq "ExternalKey")) {
            Write-Host -Object `
              "Sync-KeyProtectors: Info: I won't attempt to remove ExternalKey protectors, as they're used for auto unlock."
            
            continue :KeyProtector
          }
          Write-Host -Object `
            "Sync-KeyProtectors: Info: Key protector of type $($KeyProtector.KeyProtectorType) on volume $($Volume.MountPoint) is unwanted. Attempting to remove it."
          try {
            if ([string]$KeyProtector.KeyProtectorType -eq "Tpm" -and (!$RemoveTpm)) {
              Write-Host -Object `
                "Sync-KeyProtectors: Info: Not removing TPM protector, since RemoveTpm is false."
              continue :KeyProtector
            }
            Remove-BitLockerKeyProtector `
              -KeyProtectorId $KeyProtector.KeyProtectorId `
              -MountPoint $Volume.MountPoint
          } # try
          catch {
            Write-Error -Message `
              $_
            
            Write-Error -Message `
              "Sync-KeyProtectors: Unexpected failure in removal of key protector $($KeyProtector.KeyProtectorType) on volume $($Volume.MountPoint) with ID $($KeyProtector.KeyProtectorId)."
          } # catch Remove-BitLockerKeyProtector
        } # elseif Remove
        else {
          Write-Host -Object `
            "Sync-KeyProtectors: Info: Key protector $($KeyProtector) is not desired on volume $($Volume.MountPoint), but removal was not requested. Continuing."
        } # else

      } # foreach KeyProtector

      if ($Match -eq $DesiredMatch) {
        Write-Host -Object `
          "Sync-KeyProtectors: Info: Desired key protectors on volume $($Volume.MountPoint) match set key protectors. Good!"
        continue
      }
      if ($Match -ne $DesiredMatch) {
        Write-Host -Object `
          "Sync-KeyProtectors: Info: Desired key protectors on volume $($Volume.MountPoint) do not match set key protectors. We need to register new key protectors. $($Match), $($DesiredMatch)"
        
        Write-Host -Object `
          "Sync-KeyProtectors: Info: Attempting to add missing key protector(s) of type(s) $($DesiredProtectors) to volume $($Volume.MountPoint)."

        :AddKeyProtector foreach ($KeyProtectorType in $DesiredProtectors) {
          switch ($KeyProtectorType) {
            "RecoveryPassword" {
              try {
                Add-BitLockerKeyProtector `
                  -MountPoint $Volume.MountPoint `
                  -RecoveryPasswordProtector `
                  -ErrorAction Stop
              } # try
              catch {
                Write-Error -Message `
                  $_
                
                Write-Error -Message `
                  "Sync-KeyProtectors: Failed to add RecoveryPassword key protector."
              }
              continue AddKeyProtector
            } # RecoveryPassword
            "Tpm" {
              if ($Volume.VolumeType -eq "Data") {
                Write-Host -Object `
                  "Sync-KeyProtectors: Info: It is not possible to add a TPM protector to a data volume. Skipping this protector."
                continue AddKeyProtector
              }
              try {
                Add-BitLockerKeyProtector `
                  -MountPoint $Volume.MountPoint `
                  -TpmProtector `
                  -ErrorAction Stop
              } # try
              catch {
                Write-Error -Message `
                  $_
                
                Write-Error -Message `
                  "Sync-KeyProtectors: Failed to add Tpm key protector."
              } # catch
              continue AddKeyProtector
            } # Tpm
            default {
              Write-Error -Message `
                "Sync-KeyProtectors: I cannot add this type ($($KeyProtectorType)) of key protector."
              
              continue AddKeyProtector
            }
          } # switch KeyProtectorType
        } 
      }

    } # foreach Partition
  } # function Sync-KeyProtectors
  
} PROCESS {

  # Collect Tpm object for reuse.

  $SystemTpm = Get-Tpm

  # Confirm the system has a TPM present.

  if ($SystemTpm.TpmActivated) {
    Write-Host `
      "TPM found. Continuing."
  } else {
    Write-Host `
      "Info: This system does not have an active TPM. I won't encrypt its disks. Exiting."

    return 0
  }
  
  # Confirm that the TPM is enabled.

  if (-not $SystemTpm.TpmEnabled) {
    Write-Error `
      "TPM is active (exists), but not enabled. I won't encrypt the system's disks. Please enable the TPM and try again. Exiting."

    return 1
  }
  
  # Get a list of partitions with associated drive letters - we can enable BitLocker on these.
  # Iterate through the partitions and determine that we do want to encrypt them.

  :Partition foreach ($Partition in (Get-Partition | Where-Object DriveLetter)) {

    Write-Host -Object `
      "Info: Main loop beginning on partition $($Partition.DriveLetter)."
    
    # Get the logical disk that the partition is on

    try {
      $LogicalDisk = (
        Get-Disk `
          -Number $Partition.DiskNumber `
          -ErrorAction 'Stop'
      )
    } catch {
      Write-Warning -Message `
        "Unable to Get a logical disk corresponding to partition $($Partition.DriveLetter). Skipping partition $($Partition.DriveLetter)."
      
      continue Partition
    }

    # Get the physical disk associated with the logical disk by using the serial number, then get the physical disk's MediaType.
    # This may not work with hardware RAID or Storage Spaces, but that's OK; the partition will be skipped if media or SN cannot be determined.
  
    if ($null -eq $LogicalDisk.SerialNumber) {
      Write-Warning -Message `
        "LogicalDisk SerialNumber is null. Something may be wrong, or perhaps this is a RAID array, mounted VHDX, or a LV. You are in uncharted territory. Skipping partition $($Partition.DriveLetter)."

      continue Partition
    }
    
    if (-not $LogicalDisk.SerialNumber) {
      Write-Warning -Message `
        "LogicalDisk SerialNumber not found. Something is moderately wrong! I won't be able to determine media type. Skipping partition $($Partition.DriveLetter)."

      continue Partition
    }
    
    # PartitionMediaType = query physical disk by SN, get MediaType property. This will typically be "HDD" or "SSD."
    # Do not attempt to encrypt this volume if the volume is not on a SSD.

    if ($CheckMediaType) {

      try {

        $MediaType = (Get-PhysicalDisk `
          -SerialNumber $LogicalDisk.SerialNumber `
          -ErrorAction 'Stop'
          ).MediaType

      } catch {

        Write-Error -Message `
          $_
  
        Write-Error -Message `
          "Unable to map LogicalDisk $($LogicalDisk) to a PhysicalDisk to determine MediaType. Skipping this partition."
        
        continue Partition

      }
  
      if ($MediaType -ne "SSD") {

        Write-Host -Object `
          'Info: PartitionMediaType is not an SSD.'

        if ($EncryptSpinningDrives -and $MediaType -eq "HDD") {

          Write-Host -Object `
            'Info: Flag set to encrypt HDDs and this partition is a HDD. Continuing.'
          
        } else {

          Write-Host -Object `
            "Info: we are NOT encrypting hard disks, and MediaType is not an SSD ($($MediaType)). Skipping this partition."
  
          continue Partition

        }

      }
    
      Write-Host -Object `
        "Info: Detected that this $($Partition.DriveLetter) drive is of MediaType SSD, or it's a hard drive and we want to encrypt it. Good! Continuing."
    
      # Check if disk is fixed by querying Win32_LogicalDisk (via wrapper function)
      # for the DeviceId (C:) and using the DriveType property (-eq 3 = fixed)
      # Skip this iteration if the DeviceType is not Fixed.
      
      # handle the case where Win32_LogicalDisk is not available, e.g.,
      # if WMI repository is inconsistent. Attempt to salvage WMI repository.
      # If WMI repository is consistent, throw an error and terminate the script.
      function Get-LogicalDisk {
        param (
          [string] $DriveLetter
        )

        try {
          
          $CimInstance = (Get-CimInstance Win32_LogicalDisk -ErrorAction Stop)

        }
        catch {

          if ((& winmgmt /verifyrepository) -notcontains 'WMI repository is consistent') {

            Write-Warning -Message `
              'WMI repository is inconsistent - attempting to salvage it.'

            $Salvage = (& winmgmt /salvagerepository)

          } else {

            throw `
              "Unable to get Win32_LogicalDisk, but WMI repository is consistent. This is an unexpected failure. Terminating."

          }

          throw `
            "Unable to get Win32_LogicalDisk. Something may be wrong with the WMI repository: $($_)"

        }

        return ($CimInstance | Where-Object Name -eq "$($DriveLetter):")

      }

      $Win32_LogicalDisk = Get-LogicalDisk `
        -DriveLetter $Partition.DriveLetter
  
      if (-not $Win32_LogicalDisk) {

        Write-Warning -Message `
          "Unable to find a Win32_LogicalDisk corresponding to our DriveLetter $($DriveLetter). Without this, I cannot determine if this drive is removable. Skipping this partition."

      }
  
      if ($Win32_LogicalDisk.DriveType -eq 3) {

        Write-Host -Object `
          "Info: Win32_LogicalDisk corresponding to $($Partition.DriveLetter) is of fixed type. Continuing."

      } else {

        Write-Host -Object `
          "Info: Win32_LogicalDisk.DriveType for $($Partition.DriveLetter) on SSD media is not fixed (3), instead $($Win32_LogicalDisk.DriveType). Skipping this partition."
          
        continue Partition

      }    
    }

    # get the BitLocker volume object that corresponds to our mount point.
    try {

      $BitLockerVolume = Get-BitLockerVolume `
        -MountPoint $Partition.DriveLetter `
        -ErrorAction 'Stop'

    } catch {

      Write-Error -Message `
        "System partition with drive letter $($Partition) does not seem to have a matching BitLockerVolume object. This is unexpected. Skipping this volume."

      continue Partition

    }

    Write-Host "Info: Polling status of BitLocker volume $($BitLockerVolume.MountPoint)."

    # if the drive is already encrypted, make sure protection is off, and then enable disk encryption.
    # if we can't handle the state of the drive or don't want to mess with the drive in its current state (e.g., the drive is already encrypted and Bitlocker'd) pass.

    switch ($BitLockerVolume.VolumeStatus) {

      "FullyEncrypted" {

        Write-Host -Object `
        "Info: Volume $($BitLockerVolume.MountPoint) is already encrypted."
        # TODO: this means we need to decrypt the drive before we can do anything with it!
        
        switch ($BitLockerVolume.ProtectionStatus) {

          "On" {
            # make sure that key protectors are RecoveryKey and Tpm only. Unset others.
            Write-Host -Object `
              "Info: Volume $($BitLockerVolume.MountPoint) is already protected with BitLocker."

            Write-Host -Object `
              "Info: Proceeding to sync key protectors for volume $($BitLockerVolume.MountPoint)."

            Sync-KeyProtectors -DesiredProtectors @("Tpm", "RecoveryPassword") -Remove $true -RemoveTpm $false -BitLockerVolumes $BitLockerVolume

            continue Partition

          } # ProtectionStatus On
          "Off" {

            Write-Host -Object `
              "Info: Volume $($BitLockerVolume.MountPoint) is encrypted, but BitLocker key protectors are not configured. We need to decrypt the drive before we can do anything with it."

            Write-Host -Object `
              "Info: Beginning to decrypt volume $($BitLockerVolume.MountPoint). This may take a while. Please wait..."

            Disable-BitLocker -MountPoint $($BitLockerVolume.MountPoint)

            do {
              Start-Sleep -Seconds 30
              Write-Progress -Activity `
                "Waiting for decryption of volume $($BitLockerVolume.MountPoint) to complete... Current status: $((Get-BitLockerVolume -MountPoint $BitLockerVolume.MountPoint).EncryptionPercentage)"

            } # do

            until ((Get-BitLockerVolume -MountPoint $BitLockerVolume.MountPoint).VolumeStatus -ne "DecryptionInProgress")

            Write-Host -Object `
              "Decryption of $($BitLockerVolume.MountPoint) complete. Continuing."
            
            break
            # this requires decrypting and re-encrypting the drive
          } # ProtectionStatus Off
          default {
            # this is an unknown state that means something is wrong
          } # default
        } # switch ProtectionStatus
      } "DecryptionInProgress" {

        Write-Error -Message `
          "Unexpected state. Volume is actively being decrypted. Skipping this partition and logging an error."
        
        $EncryptionFailures++

        continue Partition

      } # DecryptionInProgress
      "EncryptionInProgress" {
        # this is not expected
        # we should verify key protectors here, too
        # the below is stuck here for the moment. IDK where it'll go.
        if ($BitLockerVolume.ProtectionStatus -ne "Off") {
          Write-Warning -Message `
            "BitLockerVolume $($BitLockerVolume.MountPoint)'s ProtectionStatus is not Off and the volume is not FullyEncrypted. I am confused. Skipping this iteration; will not attempt to encrypt this volume because current state is not understood. Perhaps this script is already running?"
          
          continue 
          
        } # if
        break
      } # EncryptionInProgress
      "FullyDecrypted" {

        Write-Host -Object `
          "Info: Volume $($BitLockerVolume.MountPoint) is FullyDecrypted. Good! Continuing."
        # we're good to go
        break

      } # FullyDecrypted
      default {

        Write-Error -Message `
          "Partition $($DriveLetter) VolumeStatus is not FullyDecrypted, EncryptionInProgress, DecryptionInProgress or FullyEncrypted: $($BitLockerVolume.VolumeStatus). This should not happen. I am confused and will skip this partition."

        continue Partition

      } # default

    } # switch
    
    Write-Host -Object `
      "Info: Drive checks passed. Enabling BitLocker encryption for volume $($BitLockerVolume.MountPoint)."

    # if a TPM protector that we request is already configured, enabling BitLocker or attempting to add a key protector will fail. At this point, anything registered is unwanted, so clear it all.
    Write-Host -Object `
      "Info: Syncing key protectors with desired state = @() (none configured)."

    Sync-KeyProtectors -DesiredProtectors @() -Remove $true -RemoveTpm $true -BitLockerVolumes $BitLockerVolume

    try {

      $Result = Enable-BitLocker `
        -MountPoint $BitLockerVolume.MountPoint `
        -UsedSpaceOnly `
        -RecoveryPasswordProtector `
        -SkipHardwareTest `

      # handle error where corrupted ReAgent.xml file will break Add-TpmProtectorInternal
      
      [string] $AddTpmProtectorInternalError = 'Add-TpmProtectorInternal : The system cannot find the file specified. (Exception from HRESULT: 0x80070002)'

      if ($Result -contains $AddTpmProtectorInternalError) {

        $ReAgentPath = 'C:\Windows\System32\Recovery\ReAgent.xml'

        Write-Error -Message `
          "Warning: Attempting to handle '$($AddTpmProtectorInternalError)' by forcing recreation of $($ReAgentPath)."

        Write-Host -Object `
          "Moving ReAgent.xml to $($ReAgentPath).old."

        Test-Path `
          -Path $ReAgentPath `
          -ErrorAction 'Stop'
        
        Move-Item `
          -Path $ReAgentPath `
          -Destination "$($ReAgentPath).old"

        try {

          $Result = Enable-BitLocker `
            -MountPoint $BitLockerVolume.MountPoint `
            -UsedSpaceOnly `
            -RecoveryPasswordProtector `
            -SkipHardwareTest `

        } catch {

          Write-Error -Message `
            'Failed to resolve 0x80070002 error. Setting ReAgent.xml back the way I found it.'
          
          Move-Item `
            -Path "$($ReAgentPath).old" `
            -Destination $ReAgentPath `
            -Force

          throw $_

        } finally {

          Remove-Item `
            -Path "$($ReAgentPath).old"
            -Confirm:$false

        }
      }
      
      Add-BitLockerKeyProtector `
        -MountPoint $BitLockerVolume.MountPoint `
        -TpmProtector

      # confirm that resultant state is EncryptionInProgress. Otherwise, log a critical error.
      if ($Result.VolumeStatus -ne "EncryptionInProgress") {

        throw `
          "Resultant state was not expected. Volume is not encrypting, instead $($Result.VolumeStatus)."

      } # if

    } # try
    catch {

      Write-Error -Message `
        $_

      Write-Error -Message `
        "Critical: Unexpected failure in drive encryption. Logging a failure and continuing to the next partition."
      
      $EncryptionFailures++

      continue Partition

    } # catch

    do {

      Start-Sleep -Seconds 30
      Write-Progress -Activity `
        "Waiting for encryption of volume $($BitLockerVolume.MountPoint) to complete... Current status: $((Get-BitLockerVolume -MountPoint $BitLockerVolume.MountPoint).EncryptionPercentage)"

    } # do
    until ((Get-BitLockerVolume -MountPoint $BitLockerVolume.MountPoint).VolumeStatus -ne "EncryptionInProgress")

    $BitLockerVolume = Get-BitLockerVolume `
      -MountPoint $BitLockerVolume.MountPoint

    if ($BitLockerVolume.VolumeStatus -ne "FullyEncrypted") {

      throw "BitLocker volume is not FullyEncrypted after encryption and wait. Fatal error."

    }

    Write-Host -Object `
      "Info: Successfully enabled BitLocker on volume $($BitLockerVolume.MountPoint)."

    # refresh object now that drive is encrypted

    if ($BitLockerVolume.VolumeType -ne 'OperatingSystem') {

      Enable-BitLockerAutoUnlock `
        -MountPoint $BitLockerVolume.MountPoint
        -Confirm:$false

    }

  } # foreach Partition

  Write-Host -Object `
    "Info: Checking to see if the machine is domain or Entra joined, so we can back up BitLocker recovery keys."

  # if the computer is domain joined, attempt to back up BitLocker key protectors to AD.

  [bool] $DomainMember = & {
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {

      Write-Host -Object `
        "Info: This computer is domain joined, according to Win32_ComputerSystem.PartOfDomain."
      
      return $true

    }
    
    Write-Host -Object `
      "Info: This machine is not domain joined, according to Win32_ComputrySystem.PartOfDomain."

    return $false

  }

  [bool] $EntraJoined = & {

    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo') {

      Write-Host -Object `
        "Info: This computer is Entra ID joined, according to HKLM:\...\CloudDomainJoin\JoinInfo's existence."
      
      return $true

    }

    Write-Host -Object `
      "Info: This computer is not Entra ID joined, according to HKLM:\...\CloudDomainJoin\JoinInfo."

    return $false
  }

  :Volume foreach ($BitLockerVolume in Get-BitLockerVolume) {

    :KeyProtector foreach ($KeyProtector in (Get-BitLockerVolume -MountPoint $BitLockerVolume.MountPoint).KeyProtector) {
      
      if ([string]$KeyProtector.KeyProtectorType -eq "RecoveryPassword") {

        try {

          if ($DomainMember) {

            Write-Host -Object `
              "Info: Attempting to back up password key protector $($KeyProtector) to Active Directory."
    
            Backup-BitLockerKeyProtector `
              -MountPoint $BitLockerVolume.MountPoint `
              -KeyProtectorId $KeyProtector.KeyProtectorId

          } # if DomainMember
    
          if ($EntraJoined) {
          
            Write-Host -Object `
              "Info: Attempting to back up password key protector $($KeyProtector) to Entra ID."
    
            BackupToAAD-BitLockerKeyProtector `
              -MountPoint $BitLockerVolume.MountPoint `
              -KeyProtectorId $KeyProtector.KeyProtectorId
    
          } # if EntraJoined

        } # try
        catch {

          Write-Error -Message `
            "Failed to back up password key protector for volume $($BitLockerVolume.MountPoint)."
          Write-Error $_

        } # catch

      } # if KeyProtectorType -eq RecoveryPassword
      
    } # foreach KeyProtector

  } # foreach Volume

} END {

  if ($LogToFile) {
    Stop-Transcript
  }

  if ($EncryptionFailures -eq 0) {
    Write-Host -Object `
      "Info: Execution completed without major errors."

    return 0
  } else {
    Write-Warning -Message `
      "Execution completed with $($EncryptionFailures) failure(s) to encrypt volumes that may be compatible. Please review logged output for more details."

    return 1
  }

} # end
