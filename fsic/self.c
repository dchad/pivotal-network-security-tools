/*
   self.c

   Title : File System Integrity Checker ICT539 Semester 2 Project
   Author: Derek Chadwick 18910502
   Date  : 24/09/2011
  
   Purpose: FSIC self test functions.
   
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fsic.h"

/*
   Function: self_test()
 
   Purpose : Check the FSIC file HMACs against the HMACs in the self test database.
   Input   : Log file.
   Output  : Returns 0 on success, 1 on fail.
*/
int self_test(FILE *log_file)
{
   FILE *sc_file = fopen(SELF_CHECK_FILE, "r");
   char *lstr = xcalloc(FSIC_PATH_MAX);
   int retval = 0;

   print_log_entry("self_test() <INFO> Testing Self....\n", log_file);

   if (sc_file == NULL)
   {
      sprintf(lstr, "self_test() <ERROR> Could not open self test database: %s\n", SELF_CHECK_FILE);
      print_log_entry(lstr, log_file);
      retval = 1;
   }
   else if (validate_files(sc_file, log_file))
   {
      sprintf(lstr, "self_test() <ERROR> Self Test Validation Failed: %s\n", SELF_CHECK_FILE);
      print_log_entry(lstr, log_file);
      retval = 1;
   }

   xfree(lstr, FSIC_PATH_MAX);

   fclose(sc_file);

   return(retval);
}

/*
   Function: update_self_test_database()
 
   Purpose : Regenerates the self test database.
   Input   : Log file.
   Output  : Detected anomalies.
*/

int update_self_test_database(FILE *log_file)
{
   FILE *sc_file = fopen(SELF_CHECK_FILE, "w");
   char *lstr = xcalloc(FSIC_PATH_MAX);

   print_log_entry("update_self_test_database() <INFO> Udpating Self Test Database....\n", log_file);

   if (sc_file == NULL)
   {
      sprintf(lstr, "update_self_test_database() <ERROR> Could not open self test database: %s\n", SELF_CHECK_FILE);
      print_log_entry(lstr, log_file);
      xfree(lstr, FSIC_PATH_MAX);
      return(1);
   }

   FILE *target_file = NULL;
   char *file_path = xcalloc(FSIC_PATH_MAX);
   char *outbuf = xcalloc(DB_LINE_MAX);
   char *hmac = xcalloc(HASH_MAX);
   int i;

   struct stat file_attr;
 
   for (i = 0; i < 4; i++)
   { 
       switch(i)
       {
          case 0: strncpy(file_path, CONFIG_FILE, strlen(CONFIG_FILE)); target_file = fopen(CONFIG_FILE, "r"); break;
          case 1: strncpy(file_path, DATABASE_FILE, strlen(DATABASE_FILE)); target_file = fopen(DATABASE_FILE, "r"); break;
          case 2: strncpy(file_path, PASSWORD_FILE, strlen(PASSWORD_FILE)); target_file = fopen(PASSWORD_FILE, "r"); break;
          case 3: strncpy(file_path, BINARY_FILE, strlen(BINARY_FILE)); target_file = fopen(BINARY_FILE, "r"); break;
       }

       if (target_file == NULL)
       {
          sprintf(lstr, "update_self_test_database() <ERROR> Could not open file: %s\n", file_path);
          print_log_entry(lstr, log_file);
          continue;
       }

       /* first check the config file */
       if (stat(file_path, &file_attr) != 0) /* get the file attributes */
       {
          sprintf(lstr, "update_self_test_database() <ERROR> Could not stat file: %s\n", file_path);
          print_log_entry(lstr, log_file);
          continue;
       }
       else
       {
          if (S_ISLNK(file_attr.st_mode) != 0) /* check for a symlink */
          {
             sprintf(lstr, "update_self_test_database() <WARNING> File is a symbolic link: %s\n", file_path);
             print_log_entry(lstr, log_file);
          }

          if (generate_file_hmac(hmac, target_file, file_attr.st_size, log_file) == 0)
          {
             strncpy(outbuf, file_path, strlen(file_path));
             strncat(outbuf, ",", 1);

             /* now string together the file attributes */
             convert_file_attributes(file_attr, outbuf);

             strncat(outbuf, hmac, strlen(hmac));

             /* now write out the database entry to the self test database */
             if (fputs(outbuf, sc_file) == EOF)
             {
                print_log_entry("update_database() <ERROR> Failed to write database file!\n", log_file);
             }

             if (DEBUG)
               printf("update_self_test_database() file HMAC: %s", outbuf);

             sprintf(lstr, "update_self_test_database() <INFO> Processed File: %s\n", file_path);
             print_log_entry(lstr, log_file);
          }
      }        
      memset(outbuf, 0, DB_LINE_MAX);
      memset(file_path, 0, FSIC_PATH_MAX);
      memset(hmac, 0, HASH_MAX);
   
      fclose(target_file);
   }

   fclose(sc_file);

   xfree(file_path, FSIC_PATH_MAX);
   xfree(outbuf, DB_LINE_MAX);
   xfree(lstr, FSIC_PATH_MAX);
   xfree(hmac, HASH_MAX);

   print_log_entry("update_self_test_database() <INFO> Completed Udpating Self Test Database....\n", log_file);

   return(0);
}

/*
   Function: validate_files()
 
   Purpose : Checks the files listed in the given db file.
   Input   : Log file, db file.
   Output  : Detected anomalies.
*/
int validate_files(FILE *db_file, FILE *log_file)
{
   int retval = 0;
   char *db_entry = xcalloc(DB_LINE_MAX);
   char *file_path = xcalloc(FSIC_PATH_MAX);
   char *db_hmac = xcalloc(HASH_MAX);
   char *hmac = xcalloc(HASH_MAX);
   char *lstr = xcalloc(FSIC_PATH_MAX);
   int i = 0;

   printf("Checking FSIC files...\n");

   if (db_file != NULL)
   {

      while (fgets(db_entry, DB_LINE_MAX, db_file))
      {
         /* file path */
         char *token = strtok(db_entry, ",");
         strncpy(file_path, token, strlen(token));

         /* get the file attributes stored in the database entry */
         struct stat db_file_attr;
         parse_file_attributes(&db_file_attr);

         /* file hmac */
         token = strtok(NULL, ",");
         strncpy(db_hmac, token, strlen(token));
       
         FILE *target_file = fopen(file_path, "r");
       
         if (target_file == NULL)
         {
            sprintf(lstr, "validate_files() <ERROR> Could not open file: %s\n", file_path);
            print_log_entry(lstr, log_file);
            memset(file_path, 0, FSIC_PATH_MAX);
            continue;
         }

         struct stat file_attr;
         if (stat(file_path, &file_attr) != 0) /* get the live file attributes */
         {
            sprintf(lstr, "validate_files() <ERROR> Could not stat file: %s\n", file_path);
            print_log_entry(lstr, log_file);
            continue;
         }
                                               /* generate the live HMAC */
         if (generate_file_hmac(hmac, target_file, file_attr.st_size, log_file) != 0)
         {
            sprintf(lstr, "validate_files() <ERROR> Could not generate HMAC for: %s\n", file_path);
            print_log_entry(lstr, log_file);
            continue;
         }

         /* compare all the file attributes and hmac */

         if (DEBUG)
            printf("Comparing file attributes: %s\n", file_path);
         
         int anomalies = check_file_attributes(file_attr, db_file_attr, file_path, log_file);

         if (strncmp(hmac, db_hmac, strlen(hmac)))
         {
            sprintf(lstr, "validate_files() <WARNING> HMAC Anomaly: %s\n", file_path);
            print_log_entry(lstr, log_file);
            anomalies++;
         }

         if (anomalies > 0)
         {
            sprintf(lstr, "validate_files() <WARNING> Found %i anomalies for file: %s\n", anomalies, file_path);
            print_log_entry(lstr, log_file);
         } 

         memset(db_entry, 0, DB_LINE_MAX); /* !!!clear the buffers!!! */
         memset(file_path, 0, FSIC_PATH_MAX);
         memset(db_hmac, 0, HASH_MAX);
         memset(hmac, 0, HASH_MAX);
         fclose(target_file);
         i++;
      }

   }
   else
   {
      print_log_entry("validate_files() <ERROR> Open Database File Failed!\n", log_file);
      retval = FILE_ERROR;
   } 
 
   xfree(file_path, FSIC_PATH_MAX);
   xfree(db_entry, DB_LINE_MAX);
   xfree(hmac, HASH_MAX);
   xfree(db_hmac, HASH_MAX);
   xfree(lstr, FSIC_PATH_MAX);

   print_log_entry("validate_files() <INFO> Completed Self Check.\n", log_file);
   printf("validate_files() : Processed %i files.\n", i);

   return(retval);
}
