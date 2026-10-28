/* Sweep every reached baseline allocation index of an untrusted peer. */
#define main baseline_main
#include "native_ca_verify.c"
#undef main
int main(int argc,char **argv){
 if(argc!=3)return 64;mbedtls_platform_set_calloc_free(alloc,dealloc);
 job j={.chain=argv[1],.host=argv[2],.expected=2};
 if(once(&j,0)!=2)return 1;size_t n=calls;
 for(size_t i=1;i<=n;i++){j.fail=i;int r=once(&j,0);if(r!=2){printf("fault=%zu ret=%d residual=%zu\n",i,r,live);return 2;}}
 printf("negative-baseline-allocation-indices=%zu all-rejected residual=0\n",n);return 0;
}
