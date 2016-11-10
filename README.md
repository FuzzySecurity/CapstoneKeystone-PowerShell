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