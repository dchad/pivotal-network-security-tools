/*
   update.c

   Title : File System Integrity Checker
   Author: Derek Chadwick
   Date  : 24/09/2011
  
   Purpose: Update file HMAC database.
   
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "fsic.h"

/*
   Function: update_database()
 
   Purpose : Reads in the config file and iterates through the files generating HMACs
           : and writing them to the database file.
   Input   : Log file, config file.
   Output  : HMAC database file.
*/
int update_database(FILE *log_file)
{
   if (log_file == NULL)
   {
      printf("update_database() <ERROR> Log File is NULL.\n");
      return(1);
   }

   FILE *config_file = NULL;
   FILE *database_file = NULL;
   char *hmac = xcalloc(HASH_MAX);
   char *lstr = xcalloc(FSIC_PATH_MAX);
   char *file_path = xcalloc(FSIC_PATH_MAX);
   char *outbuf = xcalloc(DB_LINE_MAX);
   int i = 0;
   
   printf("Starting database update...\n");
 
   /* First authenticate user via the password validation functions. */

   if (authenticate_user(log_file) != 0)
   {
      print_log_entry("update_database() <ERROR> User Authentication Failed!\n", log_file);
      return(1);
   }

   /* Open config file and database file then process each target file. */

   config_file = fopen(CONFIG_FILE, "r");
   if (config_file == NULL)
   {
      print_log_entry("update_database() <ERROR> Open Config File Failed!\n", log_file);
      return(1);
   }
   database_file = fopen(DATABASE_FILE, "w");
   if (database_file == NULL)
   {
      print_log_entry("update_database() <ERROR> Open Database File Failed!\n", log_file);
      return(1);
   }

   while (fgets(file_path, FSIC_PATH_MAX, config_file))
   {
      file_path[strlen(file_path)-1] = 0; /* get rid of the newline */

      /* validate the file path */
      if (validate_file_path(file_path, log_file) != 0)
      {
         print_log_entry("update_database() <WARNING> Invalid file path!\n", log_file);
      }

      FILE *target_file = fopen(file_path, "r");
       
      if (target_file == NULL)
      {
         sprintf(lstr, "update_database() <ERROR> Could not open file: %s\n", file_path);
         print_log_entry(lstr, log_file);
         continue;
      }

      struct stat file_attr;
      if (stat(file_path, &file_attr) != 0) /* get the file attributes */
      {
         sprintf(lstr, "update_database() <ERROR> Could not stat file: %s\n", file_path);
         print_log_entry(lstr, log_file);
         continue;
      }
      
      if (generate_file_hmac(hmac, target_file, file_attr.st_size, log_file) == 0)
      {

         if (S_ISLNK(file_attr.st_mode) != 0) /* check for a symlink */
         {
            sprintf(lstr, "update_database() <WARNING> File is a symbolic link: %s\n", file_path);
            print_log_entry(lstr, log_file);
         }

         strncpy(outbuf, file_path, strlen(file_path));
         strncat(outbuf, ",", 1);

         /* now string together the file attributes */
         convert_file_attributes(file_attr, outbuf);

         strncat(outbuf, hmac, strlen(hmac));

         /* now write out the database entry */
         if (fputs(outbuf, database_file) == EOF)
         {
            print_log_entry("update_database() <ERROR> Failed to write database file!\n", log_file);
         }

         if (DEBUG)
            printf("update_database() file HMAC: %s", outbuf);
 
         sprintf(lstr, "update_database() <INFO> Processed file: %s\n", file_path);
         print_log_entry(lstr, log_file);
        
         memset(outbuf, 0, DB_LINE_MAX);
        
      }
      else
      {
         sprintf(lstr, "update_database() <ERROR> Could not generate hmac for file: %s\n", file_path);
         print_log_entry(lstr, log_file);
      }
      memset(file_path, 0, FSIC_PATH_MAX); /* clear the buffers */
      memset(hmac, 0, HASH_MAX);
      fclose(target_file);
      i++;
   }

   xfree(file_path, FSIC_PATH_MAX);
   xfree(outbuf, DB_LINE_MAX);
   xfree(hmac, HASH_MAX);
   xfree(lstr, FSIC_PATH_MAX);

   fclose(config_file);
   fclose(database_file);

   print_log_entry("update_database() <INFO> Completed Database Update.\n", log_file);
   printf("update_database() : Processed %i files.\n", i);

   return(0);
}

/*
   Function: convert_file_attributes()
 
   Purpose : Converts stat values to string.
   Input   : stat structure and output buffer.
   Output  : String containing the file attributes.
*/
int convert_file_attributes(const struct stat file_attr, char *outbuf)
{
   char str1[20];

   if (outbuf == NULL)
   {
      printf("convert_file_attributes() <ERROR> Null Buffer.\n");
      return(1);
   }

   /* file mode and permissions */
   xitoa(file_attr.st_mode, str1, 20, 10);
   strncat(outbuf, str1, strlen(str1));
   strncat(outbuf, ",", 1);  

    /* inode number */
    xitoa(file_attr.st_ino, str1, 20, 10);
    strncat(outbuf, str1, strlen(str1));
    strncat(outbuf, ",", 1);  
         
    /* file size */
    xitoa(file_attr.st_size, str1, 20, 10);   
    strncat(outbuf, str1, strlen(str1));
    strncat(outbuf, ",", 1);  
     
    /* last modification data */
    xitoa(file_attr.st_mtime, str1, 20, 10);
    strncat(outbuf, str1, strlen(str1));
    strncat(outbuf, ",", 1);  
    
    /* file owner */
    xitoa(file_attr.st_uid, str1, 20, 10);
    strncat(outbuf, str1, strlen(str1));
    strncat(outbuf, ",", 1);  

    /* file group */
    xitoa(file_attr.st_gid, str1, 20, 10);
    strncat(outbuf, str1, strlen(str1));
    strncat(outbuf, ",", 1);  

   return(0);
}

/*
   Function: validate_file_path()
 
   Purpose : Checks the input file path for invalid characters, shell codes and other anomalies.
   Input   : Log file, file path string.
   Output  : Returns 0 if Ok or 1 if an anomaly is detected.
*/
int validate_file_path(char *fpath, FILE *log_file)
{
   /* Restrict legal path characters to [a-z][A-Z][0-9][\.-_] 
      Exclude any unusual punctuation and all non-printable characters and .. */

   if ((fpath == NULL) || (strlen(fpath) == 0) || (strlen(fpath) > FSIC_PATH_MAX) || (log_file == NULL))
   {
      printf("validate_file_path() <ERROR> Invalid Parameters.\n");
      return(1);
   }

   int path_len = strlen(fpath);
   char *lstr = xcalloc(path_len + 100);
   int i;

   if (fpath[0] != '/')
   {
      sprintf(lstr, "validate_file_path() <ERROR> Not an absolute path!: %s\n", fpath);
      print_log_entry(lstr, log_file);
      xfree(lstr, path_len + 100);
      return(1);
   }

   for (i = 0; i < strlen(fpath); i++)
   {
      /* int num = toascii(fpath[i]); */
      if ((fpath[i] < 32) || (fpath[i] > 126)) /* not a printable character !(isascii() and isprint()) */
      {
         sprintf(lstr, "validate_file_path() <ERROR> Invalid characters in path!: %s\n", fpath);
         print_log_entry(lstr, log_file);
         xfree(lstr, path_len + 100);
         return(1);
      }
   }

   /* realpath() NOT IN ANSI STANDARD!!!

   char *canonical_path;

   if ((canonical_path = realpath(fpath, NULL)) == NULL)
   {
      sprintf(lstr, "validate_file_path() <ERROR> Failed to get absolute path!: %s\n", fpath);
      print_log_entry(lstr, log_file);
      xfree(lstr, path_len + 100);
      return(1);
   }

   if (strlen(canonical_path) != strlen(fpath))
   {
      sprintf(lstr, "validate_file_path() <ERROR> File path and canonical path are not equal length!: %s\n", canonical_path);
      print_log_entry(lstr, log_file);
      xfree(lstr, path_len + 100);
      return(1);
   }

   if(strncmp(canonical_path, fpath, strlen(canonical_path)) != 0)
   {
      sprintf(lstr, "validate_file_path() <ERROR> File path and canonical path are not equal!: %s\n", canonical_path);
      print_log_entry(lstr, log_file);
      xfree(lstr, path_len + 100);
      return(1);
   }
   */

   xfree(lstr, path_len + 100);

   return(0);
}
