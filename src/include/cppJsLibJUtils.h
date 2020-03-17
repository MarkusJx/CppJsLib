#ifndef __CPPJSLIBJUTILS_H
#define __CPPJSLIBJUTILS_H

#include "graal_isolate.h"


#if defined(__cplusplus)
extern "C" {
#endif

int run_main(int paramArgc, char** paramArgv);

void vmLocatorSymbol(graal_isolatethread_t* thread);

int portInUse(graal_isolatethread_t*, size_t, int);

#if defined(__cplusplus)
}
#endif
#endif
