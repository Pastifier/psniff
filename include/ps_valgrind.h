// Valgrind threading annotations for atomic operations
// Reference: https://valgrind.org/docs/manual/hg-manual.html

#ifndef PS_VALGRIND_H
# define PS_VALGRIND_H

// Only enable annotations when running under Valgrind
#ifdef USE_VALGRIND_ANNOTATIONS
# include <valgrind/helgrind.h>
#else
// Define null macros when not using Valgrind
# define ANNOTATE_HAPPENS_BEFORE(addr)
# define ANNOTATE_HAPPENS_AFTER(addr)
# define ANNOTATE_HAPPENS_BEFORE_FORGET_ALL(addr)
#endif

#endif // !PS_VALGRIND_H
