/*
   hmac.c

   Title : File System Integrity Checker ICT539 Semester 2 Project
   Author: Derek Chadwick 18910502
   Date  : 24/09/2011
  
   Purpose: FSIC hmac functions.
   
*/

#include <mhash.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <time.h>
#include <sys/stat.h>

#include "fsic.h"

/*
   Function: generate_password_hmac()
 
   Purpose : Uses the WHIRLPOOL 512 HMAC to create a hash for a new password, uses a modified
           : form of the GNU C lib algorithm.
   Input   : Char buffers for the password and hmac value.
   Return  : HMAC
*/
int generate_password_hmac(char *pw, char *hmac)
{
   unsigned long seed[2];
   char salt[] = "$........";
   const char *const seedchars = "./-_=+[]{}0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
   MHASH td;
   unsigned char *mac;
   int i,j;

   if ((pw == NULL) || (hmac == NULL))
   {
      printf("generate_password_hmac() <ERROR> NULL parameters passed in!\n");
      return(1);
   }

   /* first generate a pseudorandom seed */
   srand(time(NULL));
   seed[0] = rand();
   srand(time(NULL));
   seed[1] = getpid() ^ (seed[0] >> 8 & rand());
     
   /* now generate the salt and pepper */
   for (i = 0; i < 8; i++)
         salt[1+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];   

   if (DEBUG)
   {
      printf("gph() Password>>> %s\n", pw);
      printf("gph() Salt>>>>>>> %s\n", salt);
   }

   /* now hash the password using the salt value as the key */
   td = mhash_hmac_init(MHASH_WHIRLPOOL, salt, strlen(salt), mhash_get_hash_pblock(MHASH_WHIRLPOOL));

   mhash(td, pw, strlen(pw));
   mac = mhash_hmac_end(td);

   strcat(hmac,salt);
   strcat(hmac,"0x");
   for (j = 0; j < mhash_get_block_size(MHASH_WHIRLPOOL); j++) 
   {
      char hex[2];
      sprintf(hex, "%.2x", mac[j]);
      strncat(hmac, hex, 2);
   }
   strcat(hmac, "\n");

   if (DEBUG)
      printf("gph() HMAC>>> %s", hmac);

   return(SUCCESS);
}

/*
   Function: get_password_hmac()
 
   Purpose : Uses the WHIRLPOOL 512 HMAC to create a password HMAC for comparison with the saved password HMAC.
   Input   : Char buffers for the password and hmac value.
   Return  : HMAC 
*/
int get_password_hmac(char *pw, char *hmac, char *salt)
{
   MHASH td;
   unsigned char *mac;
   int j;

   if ((pw == NULL) || (hmac == NULL) || (salt == NULL) || (strlen(pw) == 0) || (strlen(salt) == 0))
   {
      printf("get_password_hmac() <ERROR> NULL parameters. \n");
      return(1);
   }

   if (DEBUG)
   {
      printf("getph() Password>>> %s\n", pw);
      printf("getph() Salt>>>>>>> %s\n", salt);
   }

   /* now hash the password using the salt value as the key */
   td = mhash_hmac_init(MHASH_WHIRLPOOL, salt, strlen(salt), mhash_get_hash_pblock(MHASH_WHIRLPOOL));

   mhash(td, pw, strlen(pw));
   mac = mhash_hmac_end(td);

   strcat(hmac,salt);
   strcat(hmac,"0x");
   for (j = 0; j < mhash_get_block_size(MHASH_WHIRLPOOL); j++) 
   {
      char hex[2];
      sprintf(hex, "%.2x", mac[j]);
      strncat(hmac, hex, 2);
   }
   strcat(hmac, "\n");

   if (DEBUG)
      printf("getph() HMAC>>> %s", hmac);

   return(SUCCESS);
}

/*
   Function: generate_file_hmac()
 
   Purpose : Uses the SHA512 HMAC to create a hash for a new password, uses a modified
           : form of the GNU C lib algorithm.
   Input   : Char buffers for the password and hmac value.
   Return  : HMAC
*/
int generate_file_hmac(char *hmac, FILE *target_file, unsigned long file_size, FILE *log_file)
{
   MHASH td;
   unsigned char *mac;
   int j;
   char *cik; /* compiled-in-key */
   char *file_buffer;
   
   if (target_file == NULL)
   {
      print_log_entry("generate_file_hmac() <ERROR> Target file is null!\n", log_file);
      return(1);
   }

   if (hmac == NULL)
   {
      print_log_entry("generate_file_hmac() <ERROR> HMAC buffer is null!\n", log_file);
      return(1);
   }

   if (file_size > 0)
   {
      /* first get the file size and allocate a buffer then read in the file */
      file_buffer = xcalloc(file_size);

      /* Get file size, read in and generate hmac */
      if (fread(file_buffer, 1, file_size, target_file) == 0)
      {
         print_log_entry("generate_file_hmac() <ERROR> Read File Failed!\n", log_file);
         xfree(file_buffer, file_size);
         return(1);
      }
   }
   else
   {
      print_log_entry("generate_file_hmac() <ERROR> File is empty!\n", log_file);
      return(1);
   }

   cik = xcalloc(HASH_MAX);

   strncpy(cik, KEY1, strlen(KEY1));
   if (DEBUG)
      printf("gfh() compiled-in-key: %s\n", cik);

   /* now hash the password using the compiled-in-key */
   td = mhash_hmac_init(MHASH_SHA512, cik, strlen(cik), mhash_get_hash_pblock(MHASH_SHA512));

   mhash(td, file_buffer, file_size);
   mac = mhash_hmac_end(td);

   strcat(hmac,"0x");
   for (j = 0; j < mhash_get_block_size(MHASH_SHA512); j++) 
   {
      char hex[2];
      sprintf(hex, "%.2x", mac[j]);
      strncat(hmac, hex, 2);
   }
   strcat(hmac, "\n");

   xfree(file_buffer, file_size);
   xfree(cik, HASH_MAX);

   return(SUCCESS);
}


