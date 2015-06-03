/*
   util.c

   Title : File System Integrity Checker ICT539 Semester 2 Project
   Author: Derek Chadwick 18910502
   Date  : 24/09/2011
  
   Purpose: Wrapper functions for various standard C lib functions to
            make them safer!!!.
   
*/

#include <mhash.h>
#include <stdio.h>
#include <stdlib.h>

#include "fsic.h"

/* Redefine malloc with a fatal exit. */
void *xmalloc (size_t size)
{
   register void *value = malloc (size);
   if (value == 0)
   {
      fatal("xmalloc() <FATAL> Virtual Memory Exhausted!!!");
   }
   return value;
}

/* Redefine calloc with a fatal exit. */
void *xcalloc (size_t size)
{
   register void *value = calloc (size, 1);
   if (value == 0)
   {
      fatal("xmalloc() <FATAL> Virtual Memory Exhausted!!!");
   }
   return value;
}

/* Redefine realloc with a fatal exit. */
void *xrealloc (void *ptr, size_t size)
{
   register void *value = realloc (ptr, size);
   if (value == 0)
   {
      fatal ("xmalloc() <FATAL> Virtual Memory Exhausted");
   }
   return value;
}

/* Redefine free with buffer zeroing. */
int xfree(char *buf, int len)
{
   memset(buf, 0, len);
   free(buf);
   return(0);
}

/* Bail Out */
int fatal(char *str)
{
   printf("%s\n", str);
   exit(1);
}

/* help */
int print_help()
{
   printf("\nFile System Integrity Checker 1.0\n\n");
   printf("Command: fsic <option>\n\n");
   printf("Check files    : -c\n");
   printf("Change password: -p\n");
   printf("Update database: -u\n");
   printf("Self test      : -s\n");
   printf("\n");

   return(0);
}

/**
 * Modified version of char* style "itoa" with buffer length check.
 * (Kernighan and Ritchie)
 */
char *xitoa(int value, char* result, int len, int base) 
{

   if (base < 2 || base > 36) { *result = '\0'; return result; }
	
   char* ptr = result, *ptr1 = result, tmp_char;
   int tmp_value;
   int i = 0;
	
   do {
         tmp_value = value;
         value /= base;
         *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
      i++;
   } while ((i < len) && value );

   if (tmp_value < 0) *ptr++ = '-';
   *ptr-- = '\0';
   while(ptr1 < ptr) {
      tmp_char = *ptr;
      *ptr--= *ptr1;
      *ptr1++ = tmp_char;
   }
   return result;
}


