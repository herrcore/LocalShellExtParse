# LocalShellExtParse #
LocalShellExtParse is an "offline" forensics script that will generating a “first loaded” timeline for Shell Extensions and identifying Shell Extensions that are only installed for the current user. This is a useful way to identify malware that is using a Shell Extension as a persistence mechanism. 

_NOTE:_ This probably would have been better as a RegRipper plugin but Python is the future, and we need to collect some extra information that RegRipper doesn’t currently parse.

## Data Collection ##
The script parses entries from the *NTUSER.DAT* and *UsrClass.DAT* files. To use the tool you will first need to collect the files from the host that you want to analyze. I prefer FTK Imager (http://accessdata.com/product-download) but any tool that allows you to carve system files will work.

Everyone knows that NTUSER.DAT is located in %userprofile% but UsrClass.DAT may be less well understood. When viewing a live registry under HKEY_CURRENT_USER\Software\ there is a key called “CLSID” that shows all the CLSIDs for the current user. The data for this key is not stored in NTUSER.DAT it’s actually stored in the UsrClass.DAT file located in; `%userprofile%\AppData\Local\\Microsoft\Windows\UsrClass.dat`

## Data Parsing ##
Once the files have been collected the can be parsed by LocalShellExtParse.py to produce;  
* a timeline of the first time each Shell Extension has been loaded by the user 
* a list of all Shell Extensions that have been loaded by the user and are only installed for that user.

## Using The Script ##
By default the script will attempt to parse out both the first load timeline and the Current User Shell Extensions. If run in this mode both the UsrClass.dat and NTUSER.DAT files must be passed as arguments.

`python LocalShellExtParse.py --ntuser NTUSER.DAT --usrclass UsrClass.dat`

The script also supports a *--cached* option that only parses the Shell Extensions' first load times. If run in this mode only the NTUSER.DAT file needs to be supplied.

`python LocalShellExtParse.py --cached --ntuser NTUSER.DAT`

