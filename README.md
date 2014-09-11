RemoveSignCode
==============
Remove Authenticode (digital signature/SignCode) from Windows Executable (PE32/PE64).

Coded in C# with Visual Studio Express Editon 2010

Screenshot
==========
'''
Authenticode Removal
version 1.0
Usage: RemoveCertificate [OPTIONS]+
Remove Authenticode from Windows Executable (PE32/PE64)

Options:
  -f, --file=FILE            Remove authenticode from FILE
                               Wildcare char is allow
  -d, --directory=DIRECTORY  DIRECTORY directory to scan
                               Using with wildcare char
  -r                         Search recursivity (used with directory)
  -v                         increase debug message verbosity
  -h, --help                 show this message and exit
'''
