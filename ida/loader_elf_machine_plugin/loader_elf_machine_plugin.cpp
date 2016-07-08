#include <pro.h>
#include <idp.hpp>
#include <diskio.hpp>
#include <loader.hpp>

// Event: ELF loader machine type checkpoint.

int EM_HEXAGON = 164; // ELF e_machine: Qualcomm Hexagon processor

//--------------------------------------------------------------------------
// We hook to IDP event to receive processor module notifications
static int idaapi idp_callback(void * /*user_data*/, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    case processor_t::loader_elf_machine:
    {
      /*linput_t *li =*/ va_arg(va, linput_t *);
      int machine_type = va_arg(va, int);

      // Intercept ELF binary with Hexagon machine architecture.
      if ( machine_type == EM_HEXAGON )
      {
        const char ** p_procname = va_arg(va, const char **);

        // Set the Hexagon IDA processor module to disassemble the current binary,
        // that has its `psnames` attribute set to "QDSP6V5".
        static const char *my_proc_name = "QDSP6V5";

        *p_procname = my_proc_name;
        msg("Intercepted loader_elf_machine for QDSP6.\n");

        // The same machine type is returned, there is no need to change it.
        return machine_type;
      }
      
      break;
    }
    default:
      break;
  }

  return 0;
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  hook_to_notification_point(HT_IDP, idp_callback, NULL);
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  unhook_from_notification_point(HT_IDP, idp_callback, NULL);
}

//-------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_FIX,           // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  // long comment about the plugin
  "Intercept the event 'ELF loader machine type checkpoint' and set the Hexagon processor module. "
  "This avoids IDA's warning: 'Undefined or unknown machine type'.",
  // it could appear in the status line
  // or as a hint

  // multiline help about the plugin
  "",

  "divert_elf_machine_to_hexagon",     // the preferred short name of the plugin

  ""                // the preferred hotkey to run the plugin
};
