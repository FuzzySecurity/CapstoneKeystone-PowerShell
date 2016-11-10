Usage
-----

To use the PowerShell bindings, the entire Capstone/Keystone folders should be
added to one of the PowerShell module directories:

    # Global PSModulePath path
    %Windir%\System32\WindowsPowerShell\v1.0\Modules

    # User PSModulePath path
    %UserProfile%\Documents\WindowsPowerShell\Modules

Once this is done the modules can be initialized by using "Import-Module"
in a new PowerShell terminal. Further information on the usage of the bindings
can be obtained with the following commands:

    Get-Help Get-KeystoneAssembly -Full
    Get-Help Get-CapstoneDisassembly -Full


Notes
-----

The Keystone engine requires the Visual C++ Redistributable Packages for Visual
Studio 2013. The architecture relevant installer can be downloaded at the
following URL https://www.microsoft.com/en-gb/download/confirmation.aspx?id=40784


Library Integration
-------------------

  * A modified version of Get-KeystoneAssembly has been integrated into the
    official Keystone Engine project.

    -> https://github.com/keystone-engine/keystone/tree/master/bindings


Examples
--------

#### Get-KeystoneAssembly

```
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
```

#### Get-CapstoneDisassembly

```
# ARM simple disassembly
C:\PS> $Bytes = [Byte[]] @( 0x10, 0xf1, 0x10, 0xe7, 0x11, 0xf2, 0x31, 0xe7, 0xdc, 0xa1, 0x2e, 0xf3, 0xe8, 0x4e, 0x62, 0xf3 )
C:\PS> Get-CapstoneDisassembly -Architecture CS_ARCH_ARM -Mode CS_MODE_ARM -Bytes $Bytes
	
sdiv r0, r0, r1
udiv r1, r1, r2
vbit q5, q15, q6
vcgt.f32 q10, q9, q12

# X86 detailed disassembly, ATT syntax
C:\PS> $Bytes = [Byte[]] @( 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xF7, 0xF3 )
C:\PS> Get-CapstoneDisassembly -Architecture CS_ARCH_X86 -Mode CS_MODE_32 -Bytes $Bytes -Syntax ATT -Detailed

Size     : 5
Address  : 0x100000
Mnemonic : movl
Operands : $0xa, %eax
Bytes    : {184, 10, 0, 0...}
RegRead  :
RegWrite :

Size     : 2
Address  : 0x100005
Mnemonic : divl
Operands : %ebx
Bytes    : {247, 243, 0, 0...}
RegRead  : {eax, edx}
RegWrite : {eax, edx, eflags}
```