function Get-KeystoneAssembly {
<#
.SYNOPSIS
	Powershell wrapper for Keystone (using inline C#).

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER Architecture
	Architecture type.

.PARAMETER Mode
	Mode type.

.PARAMETER Code
	Assembly string, use ";" or multi-line variables for instruction separation.

.PARAMETER Syntax
	Syntax for input assembly.

.PARAMETER Version
	Print ASCII version banner.

.EXAMPLE

	# Support for multi-line code blocks
	PS C:\> $Code = @"
	>> sub esp, 200
	>> pop eax
	>> pop ecx
	>> ret
	>> "@
	PS C:\> Get-KeystoneAssembly -Architecture KS_ARCH_X86 -Mode KS_MODE_32 -Code $Code

	Bytes        : 9
	Instructions : 4
	PSArray      : {0x81, 0xEC, 0xC8, 0x00...}
	CArray       : {\x81, \xEC, \xC8, \x00...}
	RawArray     : {81, EC, C8, 00...}

.EXAMPLE

	# Get-KeystoneAssembly emits objects
	PS C:\> $Code = @"
	>> sub esp, 200
	>> pop eax
	>> pop ecx
	>> ret
	>> "@
	PS C:\> $Object = Get-KeystoneAssembly -Architecture KS_ARCH_X86 -Mode KS_MODE_32 -Code $Code
	PS C:\> $Object.RawArray -join ""
	81ECC80000005859C3
	PS C:\> $Object.CArray -join ""
	\x81\xEC\xC8\x00\x00\x00\x58\x59\xC3
	PS C:\> "`$Shellcode = {" + $($Object.PSArray -join ", ") + "}"
	$Shellcode = {0x81, 0xEC, 0xC8, 0x00, 0x00, 0x00, 0x58, 0x59, 0xC3}

#>

	param(
		[Parameter(ParameterSetName='Keystone', Mandatory = $True)]
		[ValidateSet(
			'KS_ARCH_ARM',
			'KS_ARCH_ARM64',
			'KS_ARCH_MIPS',
			'KS_ARCH_X86',
			'KS_ARCH_PPC',
			'KS_ARCH_SPARC',
			'KS_ARCH_SYSTEMZ',
			'KS_ARCH_HEXAGON',
			'KS_ARCH_MAX')
		]
		[String]$Architecture,
		
		[Parameter(ParameterSetName='Keystone', Mandatory = $True)]
		[ValidateSet(
			'KS_MODE_LITTLE_ENDIAN',
			'KS_MODE_BIG_ENDIAN',
			'KS_MODE_ARM',
			'KS_MODE_THUMB',
			'KS_MODE_V8',
			'KS_MODE_MICRO',
			'KS_MODE_MIPS3',
			'KS_MODE_MIPS32R6',
			'KS_MODE_MIPS32',
			'KS_MODE_MIPS64',
			'KS_MODE_16',
			'KS_MODE_32',
			'KS_MODE_64',
			'KS_MODE_PPC32',
			'KS_MODE_PPC64',
			'KS_MODE_QPX',
			'KS_MODE_SPARC32',
			'KS_MODE_SPARC64',
			'KS_MODE_V9')
		]
		[String]$Mode,
		
		[Parameter(ParameterSetName='Keystone', Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[string]$Code,
		
		[Parameter(ParameterSetName='Keystone', Mandatory = $False)]
		[ValidateSet(
			'KS_OPT_SYNTAX_INTEL',
			'KS_OPT_SYNTAX_ATT',
			'KS_OPT_SYNTAX_NASM',
			'KS_OPT_SYNTAX_MASM',
			'KS_OPT_SYNTAX_GAS')
		]
		[String]$Syntax = "KS_OPT_SYNTAX_INTEL",
		
		[Parameter(ParameterSetName='Version', Mandatory = $False)]
		[switch]$Version = $null
    )

	# Compatibility for PS v2 / PS v3+
	if(!$PSScriptRoot) {
		$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
	}
	
	# Set the keystone DLL path
	if ([IntPtr]::Size -eq 4){
		$DllPath = $($PSScriptRoot + '\Lib\Keystone-0.9.1\x86\keystone.dll').Replace('\','\\')
	} else {
		$DllPath = $($PSScriptRoot + '\Lib\Keystone-0.9.1\x64\keystone.dll').Replace('\','\\')
	}

	# Inline C# to parse the unmanaged keystone DLL
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	public enum ks_err : int
	{
		KS_ERR_OK = 0,      /// No error: everything was fine
		KS_ERR_NOMEM,       /// Out-Of-Memory error: ks_open(), ks_emulate()
		KS_ERR_ARCH,        /// Unsupported architecture: ks_open()
		KS_ERR_HANDLE,      /// Invalid handle
		KS_ERR_MODE,        /// Invalid/unsupported mode: ks_open()
		KS_ERR_VERSION,     /// Unsupported version (bindings)
		KS_ERR_OPT_INVALID, /// Unsupported option
		
		/// generic input assembly errors - parser specific
		KS_ERR_ASM_EXPR_TOKEN = 128,        /// unknown token in expression
		KS_ERR_ASM_DIRECTIVE_VALUE_RANGE,   /// literal value out of range for directive
		KS_ERR_ASM_DIRECTIVE_ID,            /// expected identifier in directive
		KS_ERR_ASM_DIRECTIVE_TOKEN,         /// unexpected token in directive
		KS_ERR_ASM_DIRECTIVE_STR,           /// expected string in directive
		KS_ERR_ASM_DIRECTIVE_COMMA,         /// expected comma in directive
		KS_ERR_ASM_DIRECTIVE_RELOC_NAME,    /// expected relocation name in directive
		KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN,   /// unexpected token in .reloc directive
		KS_ERR_ASM_DIRECTIVE_FPOINT,        /// invalid floating point in directive
		KS_ERR_ASM_DIRECTIVE_UNKNOWN,       /// unknown directive
		KS_ERR_ASM_DIRECTIVE_EQU,           /// invalid equal directive
		KS_ERR_ASM_DIRECTIVE_INVALID,       /// (generic) invalid directive
		KS_ERR_ASM_VARIANT_INVALID,         /// invalid variant
		KS_ERR_ASM_EXPR_BRACKET,            /// brackets expression not supported on this target
		KS_ERR_ASM_SYMBOL_MODIFIER,         /// unexpected symbol modifier following '@'
		KS_ERR_ASM_SYMBOL_REDEFINED,        /// invalid symbol redefinition
		KS_ERR_ASM_SYMBOL_MISSING,          /// cannot find a symbol
		KS_ERR_ASM_RPAREN,                  /// expected ')' in parentheses expression
		KS_ERR_ASM_STAT_TOKEN,              /// unexpected token at start of statement
		KS_ERR_ASM_UNSUPPORTED,             /// unsupported token yet
		KS_ERR_ASM_MACRO_TOKEN,             /// unexpected token in macro instantiation
		KS_ERR_ASM_MACRO_PAREN,             /// unbalanced parentheses in macro argument
		KS_ERR_ASM_MACRO_EQU,               /// expected '=' after formal parameter identifier
		KS_ERR_ASM_MACRO_ARGS,              /// too many positional arguments
		KS_ERR_ASM_MACRO_LEVELS_EXCEED,     /// macros cannot be nested more than 20 levels deep
		KS_ERR_ASM_MACRO_STR,               /// invalid macro string
		KS_ERR_ASM_MACRO_INVALID,           /// invalid macro (generic error)
		KS_ERR_ASM_ESC_BACKSLASH,           /// unexpected backslash at end of escaped string
		KS_ERR_ASM_ESC_OCTAL,               /// invalid octal escape sequence  (out of range)
		KS_ERR_ASM_ESC_SEQUENCE,            /// invalid escape sequence (unrecognized character)
		KS_ERR_ASM_ESC_STR,                 /// broken escape string
		KS_ERR_ASM_TOKEN_INVALID,           /// invalid token
		KS_ERR_ASM_INSN_UNSUPPORTED,        /// this instruction is unsupported in this mode
		KS_ERR_ASM_FIXUP_INVALID,           /// invalid fixup
		KS_ERR_ASM_LABEL_INVALID,           /// invalid label
		KS_ERR_ASM_FRAGMENT_INVALID,        /// invalid fragment
		
		/// generic input assembly errors - architecture specific
		KS_ERR_ASM_INVALIDOPERAND = 512,
		KS_ERR_ASM_MISSINGFEATURE,
		KS_ERR_ASM_MNEMONICFAIL,
	}

	public enum ks_arch : int
	{
		KS_ARCH_ARM = 1,    /// ARM architecture (including Thumb, Thumb-2)
		KS_ARCH_ARM64,      /// ARM-64, also called AArch64
		KS_ARCH_MIPS,       /// Mips architecture
		KS_ARCH_X86,        /// X86 architecture (including x86 & x86-64)
		KS_ARCH_PPC,        /// PowerPC architecture (currently unsupported)
		KS_ARCH_SPARC,      /// Sparc architecture
		KS_ARCH_SYSTEMZ,    /// SystemZ architecture (S390X)
		KS_ARCH_HEXAGON,    /// Hexagon architecture
		KS_ARCH_MAX,
	}

	public enum ks_mode : int
	{
		KS_MODE_LITTLE_ENDIAN = 0,    /// little-endian mode (default mode)
		KS_MODE_BIG_ENDIAN = 1 << 30, /// big-endian mode
		/// arm / arm64
		KS_MODE_ARM = 1 << 0,         /// ARM mode
		KS_MODE_THUMB = 1 << 4,       /// THUMB mode (including Thumb-2)
		KS_MODE_V8 = 1 << 6,          /// ARMv8 A32 encodings for ARM
		/// mips
		KS_MODE_MICRO = 1 << 4,       /// MicroMips mode
		KS_MODE_MIPS3 = 1 << 5,       /// Mips III ISA
		KS_MODE_MIPS32R6 = 1 << 6,    /// Mips32r6 ISA
		KS_MODE_MIPS32 = 1 << 2,      /// Mips32 ISA
		KS_MODE_MIPS64 = 1 << 3,      /// Mips64 ISA
		/// x86 / x64
		KS_MODE_16 = 1 << 1,          /// 16-bit mode
		KS_MODE_32 = 1 << 2,          /// 32-bit mode
		KS_MODE_64 = 1 << 3,          /// 64-bit mode
		/// ppc 
		KS_MODE_PPC32 = 1 << 2,       /// 32-bit mode
		KS_MODE_PPC64 = 1 << 3,       /// 64-bit mode
		KS_MODE_QPX = 1 << 4,         /// Quad Processing eXtensions mode
		/// sparc
		KS_MODE_SPARC32 = 1 << 2,     /// 32-bit mode
		KS_MODE_SPARC64 = 1 << 3,     /// 64-bit mode
		KS_MODE_V9 = 1 << 4,          /// SparcV9 mode
	}

	public enum ks_opt_value : uint
	{
		KS_OPT_SYNTAX_INTEL = 1 << 0, /// X86 Intel syntax - default on X86 (KS_OPT_SYNTAX).
		KS_OPT_SYNTAX_ATT   = 1 << 1, /// X86 ATT asm syntax (KS_OPT_SYNTAX).
		KS_OPT_SYNTAX_NASM  = 1 << 2, /// X86 Nasm syntax (KS_OPT_SYNTAX).
		KS_OPT_SYNTAX_MASM  = 1 << 3, /// X86 Masm syntax (KS_OPT_SYNTAX) - unsupported yet.
		KS_OPT_SYNTAX_GAS   = 1 << 4, /// X86 GNU GAS syntax (KS_OPT_SYNTAX).
	}

	public static class Keystone
	{
		[DllImport("$DllPath")]
		public static extern ks_err ks_open(
			ks_arch arch,
			ks_mode mode,
			ref IntPtr handle);

		[DllImport("$DllPath")]
		public static extern ks_err ks_option(
			IntPtr handle,
			int mode,
			ks_opt_value value);

		[DllImport("$DllPath")]
		public static extern int ks_asm(
			IntPtr handle,
			String assembly,
			ulong address,
			ref IntPtr encoding,
			ref uint encoding_size,
			ref uint stat_count);

		[DllImport("$DllPath")]
		public static extern ks_err ks_errno(
			IntPtr handle);

		[DllImport("$DllPath")]
		public static extern ks_err ks_close(
			IntPtr handle);

		[DllImport("$DllPath")]
		public static extern void ks_free(
			IntPtr handle);

		[DllImport("$DllPath")]
		public static extern int ks_version(
			uint major,
			uint minor);
	}
"@

	if ($Version){
		$VerCount = [System.BitConverter]::GetBytes($([Keystone]::ks_version($null,$null)))
		$Banner = @"

                ;#                 
             #########             
           ######""   ;;           
     ###";#### ;##############     
   ##### ### ##""   "## ""######   
   #### ###           ""### "###   
   #### ##               "### "#   
   "### \#               ; ####    
    "### "               ##"####   
   ## \###               ## ####   
   #### "###;           ### ####   
   ######## "#"   ;### ###"#####   
     "#############" ####"/##"     
           "    ;#######           
             "#######"             
                 #                 

     -=[Keystone Engine v$($VerCount[1]).$($VerCount[0])]=-

"@
		# Mmm ASCII version banner!
		$Banner
		Return
	}

	# Asm Handle
	$AsmHandle = [IntPtr]::Zero

	# Initialize Keystone with ks_open()
	$CallResult = [Keystone]::ks_open($Architecture,$Mode,[ref]$AsmHandle)
	if ($CallResult -ne "KS_ERR_OK") {
		if ($CallResult -eq "KS_ERR_MODE"){
			echo "`n[!] Invalid Architecture/Mode combination"
			echo "[>] Quitting..`n"
		} else {
			echo "`n[!] cs_open error: $CallResult"
			echo "[>] Quitting..`n"
		}
		Return
	}

	# Only one ks_opt_type -> KS_OPT_SYNTAX = 1
	$CallResult = [Keystone]::ks_option($AsmHandle, 1, $Syntax)
	if ($CallResult -ne "KS_ERR_OK") {
		echo "`n[!] ks_option error: $CallResult"
		echo "[>] Quitting..`n"
		$CallResult = [Keystone]::ks_close($AsmHandle)
		Return
	}

	# Result variables
	$Encoded = [IntPtr]::Zero
	[int]$Encoded_size = 0
	[int]$Stat_count = 0

	# Assemble instructions
	$CallResult = [Keystone]::ks_asm($AsmHandle, $Code, 0, [ref]$Encoded, [ref]$Encoded_size, [ref]$stat_count)

	if ($CallResult -ne 0) {
		echo "`n[!] ks_asm error: $([Keystone]::ks_errno($AsmHandle))"
		echo "[>] Quitting..`n"
		$CallResult = [Keystone]::ks_close($AsmHandle)
		Return
	} else {
		$BufferOffset = $Encoded.ToInt64()

		if ($Encoded_size -gt 0) {
			# PS/C# hex array
			$PSArray = @()
			# C-style hex array
			$CArray = @()
			# Raw hex array
			$RawArray = @()
			for ($i=0; $i -lt $Encoded_size; $i++) {
				$PSArray += echo "0x$("{0:X2}" -f $([Runtime.InteropServices.Marshal]::ReadByte($BufferOffset)))"
				$CArray += echo "\x$("{0:X2}" -f $([Runtime.InteropServices.Marshal]::ReadByte($BufferOffset)))"
				$RawArray += echo "$("{0:X2}" -f $([Runtime.InteropServices.Marshal]::ReadByte($BufferOffset)))"
				$BufferOffset = $BufferOffset+1
			}
			# Result Object
			$HashTable = @{
				Bytes = $Encoded_size
				Instructions = $stat_count
				PSArray = $PSArray
				CArray = $CArray
				RawArray = $RawArray
			}
			New-Object PSObject -Property $HashTable |Select-Object Bytes,Instructions,PSArray,CArray,RawArray

			# Clean up!
			[Keystone]::ks_free($Encoded)
			$CallResult = [Keystone]::ks_close($AsmHandle)
		} else {
			echo "`n[!] No bytes assembled"
			echo "[>] Quitting..`n"
			$CallResult = [Keystone]::ks_close($AsmHandle)
			Return
		}
	}
}