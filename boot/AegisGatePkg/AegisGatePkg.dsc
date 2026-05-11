## @file
#  AegisGate Platform Description File
#  Build configuration for the UEFI bootloader.
#
#  Developer: Nik
#  Copyright (c) 2026. All rights reserved.
##

[Defines]
  PLATFORM_NAME           = AegisGatePkg
  PLATFORM_GUID           = B1C2D3E4-F5A6-7890-ABCD-EF1234567891
  PLATFORM_VERSION        = 1.0
  DSC_SPECIFICATION       = 0x00010006
  OUTPUT_DIRECTORY        = Build/AegisGate
  SUPPORTED_ARCHITECTURES = X64
  BUILD_TARGETS           = DEBUG|RELEASE
  SKUID_IDENTIFIER        = DEFAULT

[LibraryClasses]
  # UEFI infrastructure
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

  # Base utilities
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf

  # Device Path
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf

  # Register filter (required by BaseLib on some EDK2 versions)
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf

[Components]
  AegisGatePkg/AegisGate.inf
