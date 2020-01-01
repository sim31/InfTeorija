#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #define WINDOWS // uzkomentuot linuxams
#ifdef WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

int main()
{
    printf("Hello world!\n");
    return 0;
}
