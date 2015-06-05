#!/usr/bin/env python
#######################################################################
##
## Local Shell Extension Parser
##
## Build a timeline of the first load time for all 
## shell extensions loaded by the user.
##
## List all shell extensions installed only for the current user.
##
#######################################################################


import datetime
import struct
import operator
import sys
import argparse

try:
    import hivex
except:
    print >>sys.stderr, 'Error - Please ensure you install the Hivex library, part of libguestfs, before running this script (http://libguestfs.org/).'
    sys.exit(1)

def getFiletime(int_time):
    """
    Returns int64 time as datetime
    """
    microseconds = int_time / 10
    seconds, microseconds = divmod(microseconds, 1000000)
    days, seconds = divmod(seconds, 86400)
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(days, seconds, microseconds)

def getCacheExtList(dat_location):
    """
    Parse Shell Extensions in HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached

    dat_location String: path to NTUSER.DAT file

    Return Dictionary: f(CLSID) = timestamp
    """
    ext_list={}

    try:
        h = hivex.Hivex(dat_location)
    except:
        print >>sys.stderr, 'Error - Unable to open supplied NTUSER.DAT file'
        sys.exit(1)

    key = h.root()
    key = h.node_get_child(key,"Software")
    key = h.node_get_child(key,"Microsoft")
    key = h.node_get_child(key,"Windows")
    key = h.node_get_child(key,"CurrentVersion")
    key = h.node_get_child(key,"Shell Extensions")
    key = h.node_get_child(key,"Cached")

    cached_values = h.node_values(key)
    for entry in cached_values:
        #parse the Shell Extension CLSID from the entry
        entry_name = h.value_key(entry)
        extension_CLSID = entry_name.split(' ')[0]

        #parse the first load time from the entry
        entry_value = h.value_value(entry)[1]
        if len(entry_value) == 16:
            bin_time = entry_value[8:]
            int_time = struct.unpack('<q',bin_time)[0]
        else:
            print >>sys.stderr, 'Error - Unable to parse timestamp value from Cache entry: %s' % entry_name
            continue
        ext_list[extension_CLSID] = int_time
    return ext_list

def getUserExtList(dat_location, loaded_ext):
    """
    Find all Shell Extensions from input list that are located in in HKEY_CURRENT_USER\Software\Classes\CLSID

    dat_location String: path to UsrClass.dat file

    loaded_ext Dictonary: f(CLSID)=timestamp. Each key is a string representing a Shell Extension CLSID that has been loaded. 

    Return Dictionary: F(CLSID) = "path to Extension Handler DLL"
    """

    ext_list={}

    try:
        h = hivex.Hivex(dat_location)
    except:
        print >>sys.stderr, 'Error - Unable to open supplied UsrClass.dat file'
        sys.exit(1)

    key = h.root()
    key = h.node_get_child(key,"CLSID")

    for ext_key in loaded_ext.keys():
        try:
            tmp_key = h.node_get_child(key, ext_key)
            tmp_key = h.node_get_child(tmp_key,'InprocServer32')
            val = h.node_get_value(tmp_key,'')
            ext_path = h.value_string(val)
            ext_list[ext_key] = ext_path
        except:
            continue
    return ext_list




def main():
    desc='''
    This script can be used to parse the first load time for all Shell Extensions loaded by a user. 
    It can also prase out Shell Extensions that have been installed only for the user. 
    This will catch malware persistence mechanisms that rely on per-user installed Shell Extensions.
    '''
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('--ntuser', action="store", dest="ntuser_dat",help="NTUSER.DAT file to parse")
    parser.add_argument('--usrclass', action="store", dest="usrclass_dat",help="UsrClass file to parse")
    parser.add_argument('-c','--cached',dest="cached_only",action='store_true',default=False,help="If you only want to get a timeline for the first load Shell Extensions. You only need to supply NTUSER.DAT with this option.")
    args = parser.parse_args()

    if args.cached_only:
        if not args.ntuser_dat:
            print >>sys.stderr, 'Error - You must supply an NTUSER.DAT file.\n\n'
            parser.print_help()
            sys.exit(1)
        else:
            cached_ext_list = getCacheExtList(args.ntuser_dat)
    else:
        if not args.ntuser_dat:    
            print >>sys.stderr, 'Error - You must supply an NTUSER.DAT file.\n\n'
            parser.print_help()
            sys.exit(1)
        elif not args.usrclass_dat:
            print >>sys.stderr, 'Error - You must supply an UsrClass3.dat file.\n\n'
            parser.print_help()
            sys.exit(1)
        else:
            cached_ext_list = getCacheExtList(args.ntuser_dat)
            local_ext_list = getUserExtList(args.usrclass_dat, cached_ext_list)

    #print the results
    #print a chronological list of all loaded Shell Extensions
    print "\n\n============ Shell Extensions First Load Times ============\n"
    sorted_ext_list = sorted(cached_ext_list.items(), key=operator.itemgetter(1))
    for entry in sorted_ext_list:
        file_time = getFiletime(entry[1])
        print entry[0]+": "+ format(file_time, '%a, %d %B %Y %H:%M:%S %Z')

    if not args.cached_only:
        #print the Shell Extensions that have been found local
        print "\n\n============ Shell Extensions Installed for Current User ============\n"
        for entry in local_ext_list.keys():
            print entry +': '+ local_ext_list[entry]



if __name__ == '__main__':
    main()



