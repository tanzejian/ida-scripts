#!/usr/bin/env python

# Script maps a hotkey(Ctrl-Alt-F) to a workaround (https://hex-rays.com/products/ida/news/7_2/the_mac_rundown/)
# which fixes the broken tail calls. Provides another hotkey(Ctrl-Alt-E) to overwrite the function end address, 
# allowing IDA to decompile properly 

import ida_kernwin
import ida_auto
import ida_funcs

CONTEXT_MENU_PATH = 'iOS Fix/'

class NoRetFix(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        func_ea = ctx.cur_value 
        if func_ea != BADADDR:
            func = ida_funcs.get_func(func_ea)
            if func is not None and (func.flags & FUNC_NORET) != 0:
                func.flags &= ~FUNC_NORET
                ida_funcs.update_func(func)
                ida_auto.reanalyze_callers(func.start_ea, False)
                print(f'[+] Fixed: {ida_funcs.get_func_name(func_ea)}@{hex(func_ea)}')
                return 1
        return 0
        
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class EndEAFix(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        addr = ctx.cur_ea
        while ida_funcs.get_func(addr) == None:
            addr -= 4
        found_func = ida_funcs.get_func(addr)
        found_func_name = ida_funcs.get_func_name(found_func.start_ea)
        print(f"[+] Found function {found_func_name}")
        found_func.end_ea = ctx.cur_ea + 4 # put cursor at the last instruction
        print(f"[+] End EA for {found_func_name} set to {hex(ctx.cur_ea + 4)}")
        return 1
        
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
    
class ContextHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        tft = ida_kernwin.get_widget_type(form)
        if tft == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(
                form,
                popup,
                'ios:noretfix',
                CONTEXT_MENU_PATH,
                ida_kernwin.SETMENU_INS,
            )
            ida_kernwin.attach_action_to_popup(
                form,
                popup,
                'ios:endeafix',
                CONTEXT_MENU_PATH,
                ida_kernwin.SETMENU_INS,
            )
        elif tft == ida_kernwin.BWN_PSEUDOCODE:
            pass

noretfix_desc = ida_kernwin.action_desc_t('ios:noretfix', 'Fix function broken tail', NoRetFix(), 'Ctrl+Alt+F')
endeafix_desc = ida_kernwin.action_desc_t('ios:endeafix', 'Fix end address', EndEAFix(), 'Ctrl+Alt+E')
ida_kernwin.register_action(noretfix_desc)
ida_kernwin.register_action(endeafix_desc)
hooks = ContextHooks()
hooks.hook()