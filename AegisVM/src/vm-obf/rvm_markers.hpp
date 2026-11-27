//  Usage:
//    #include "rvm_markers.hpp"
//    uint64_t my_func(uint64_t x) {
//        RVM_BEGIN("my_func");
//        //  code to virtualize 
//        RVM_END();
//        return result;
//    }

#pragma once

#if defined(_MSC_VER)
#include <intrin.h>   
#endif

#ifdef __cplusplus
extern "C" {
#endif

void __aegis_marker_begin(void);
void __aegis_marker_end(void);


#if defined(_MSC_VER)
  #define RVM_COMPILER_BARRIER()  _ReadWriteBarrier()
#elif defined(__GNUC__) || defined(__clang__)
  #define RVM_COMPILER_BARRIER()  __asm__ __volatile__("" ::: "memory")
#else
  #define RVM_COMPILER_BARRIER()  ((void)0)
#endif

#define RVM_BEGIN(name)  (__aegis_marker_begin(), RVM_COMPILER_BARRIER())
#define RVM_END()        (RVM_COMPILER_BARRIER(), __aegis_marker_end())

#ifdef __cplusplus
}
#endif
