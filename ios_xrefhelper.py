#!/usr/bin/env python

# Each entry in the __objc_methlist has an entry like this 
# struct method_t {
#     SEL name;
#     const char *types;
#     IMP imp;
# }
# The normal Xref only finds xrefs the imp field which is dynamically resolved at Obj-C runtime 
# from the name by objc_msgSend. This script finds the __objc_selrefs address (SEL) of the 
# desired function and Xref it, without modifying with the idb
# Note: Only works after IDA finishes caching the functions

import ida_kernwin
import ida_xref
import idautils

def find_sel_ref(ea):
    for xref in idautils.XrefsTo(ea, 0):
        if get_segm_name(xref.frm) == '__objc_methlist':
            sel_ref_addr = ida_xref.get_first_dref_from(xref.frm - 8)
            if get_segm_name(sel_ref_addr) == '__objc_selrefs':
                return sel_ref_addr
    return None

def xref_selref():
    sel_ref_addr = find_sel_ref(here())
    if sel_ref_addr != None:
        ida_kernwin.open_xrefs_window(sel_ref_addr)

hotkey_ctx = ida_kernwin.add_hotkey("Alt-Shift-X", xref_selref)