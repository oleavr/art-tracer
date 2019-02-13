#include <class_linker.h>
#include <runtime.h>

using art::Runtime;
using art::Thread;
using art::instrumentation::InstrumentationStackFrame;

extern "C"
{
  unsigned int
  ath_get_offset_of_runtime_instrumentation ()
  {
    return offsetof (Runtime, instrumentation_);
  }

  InstrumentationStackFrame *
  ath_thread_get_instrumentation_stack_front (Thread * thread)
  {
    return &thread->GetInstrumentationStack ()->front ();
  }

  InstrumentationStackFrame *
  ath_thread_get_instrumentation_stack_back (Thread * thread)
  {
    return &thread->GetInstrumentationStack ()->back ();
  }
};
