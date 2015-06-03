/*
   check.c

   Title : File System Integrity Checker ICT539 Semester 2 Project
   Author: Derek Chadwick 18910502
   Date  : 24/09/2011
  
   Purpose: Performs file integrity check against the HMAC database.
   
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fsic.h"

/*
   Function: check_files()
 
   Purpose : Reads in the database file and iterates through the files, generates new HMACs
           : and compares the file attributes and HMACs.
   Input   : Log file, database file.
   Output  : Logs errors and anomalies.
*/
int check_files(FILE *log_file)
{
   if (log_file == NULL)
   {
      printf("check_files() <ERROR> Log File is NULL!\n");
      return(1);
   }

   int retval = 0;
   FILE *db_file = fopen(DATABASE_FILE, "r");
   char *db_entry = xcalloc(DB_LINE_MAX);
   char *file_path = xcalloc(FSIC_PATH_MAX);
   char *db_hmac = xcalloc(HASH_MAX);
   char *hmac = xcalloc(HASH_MAX);
   char *lstr = xcalloc(FSIC_PATH_MAX);
   int i = 0;

   printf("Checking files...\n");

   if (db_file != NULL)
   {

      while (fgets(db_entry, DB_LINE_MAX, db_file))
      {
         /* validate db entry */

         if (validate_db_line(db_entry, log_file) != 0)
         {
             print_log_entry("check_files() <ERROR> Invalid Database Entry!\n", log_file);
             continue;
         }
       
         /* file path */
         char *token = strtok(db_entry, ",");
         if (token == NULL)
         {
             print_log_entry("check_files() <ERROR> File path not found in database entry!\n", log_file);
             continue;
         }
         strncpy(file_path, token, strlen(token));
     
         /* get the file attributes stored in the databse entry */
         struct stat db_file_attr;
         if (parse_file_attributes(&db_file_attr) == 1)
         {
             print_log_entry("check_files() <ERROR> File attributes not found in database entry!\n", log_file);
             continue;
         }

         /* file hmac */
         token = strtok(NULL, ",");
         if (token == NULL)
         {
             print_log_entry("check_files() <ERROR> HMAX not found in database entry!\n", log_file);
             continue;
         }
         strncpy(db_hmac, token, strlen(token));
       
         FILE *target_file = fopen(file_path, "r");
       
         if (target_file == NULL)
         {
            sprintf(lstr, "check_files() <ERROR> Could not open file: %s\n", file_path);
            print_log_entry(lstr, log_file);
            continue;
         }

         struct stat file_attr;
         if (stat(file_path, &file_attr) != 0) /* get the live file attributes */
         {
            sprintf(lstr, "check_files() <ERROR> Could not stat file: %s\n", file_path);
            print_log_entry(lstr, log_file);
            continue;
         }
                                               /* generate the live HMAC */
         if (generate_file_hmac(hmac, target_file, file_attr.st_size, log_file) != 0)
         {
            sprintf(lstr, "check_files() <ERROR> Could not generate HMAC for: %s\n", file_path);
            print_log_entry(lstr, log_file);
         }

         /* compare all the file attributes and hmac */

         if (DEBUG)
            printf("Comparing file attributes: %s\n", file_path);
         
         int anomalies = check_file_attributes(file_attr, db_file_attr, file_path, log_file);

         if (strncmp(hmac, db_hmac, strlen(hmac)))
         {
            sprintf(lstr, "check_files() <WARNING> HMAC Anomaly: %s\n", file_path);
            print_log_entry(lstr, log_file);
            anomalies++;
         }

         if (anomalies > 0)
         {
            sprintf(lstr, "check_files() <WARNING> Found %i anomalies for file: %s\n", anomalies, file_path);
            print_log_entry(lstr, log_file);
         }
         else
         {
            sprintf(lstr, "check_files() <INFO> No anomalies for file: %s\n", file_path);
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
      print_log_entry("check_files() <ERROR> Open Database File Failed!\n", log_file);
      retval = FILE_ERROR;
   } 
 
   xfree(file_path, FSIC_PATH_MAX);
   xfree(db_entry, DB_LINE_MAX);
   xfree(hmac, HASH_MAX);
   xfree(lstr, HASH_MAX);

   fclose(db_file);

   print_log_entry("check_files() <INFO> Completed Database Check.\n", log_file);
   printf("check_files() : Processed %i files.\n", i);

   return(retval);
}

/*
   Function: check_file_attributes()
 
   Purpose : Compares the database entry attributes and the live file attributes.
   Input   : stat structures for db and live.
   Output  : Returns anomaly count.
*/
int check_file_attributes(const struct stat db_file_attr, const struct stat live_file_attr, char *file_path, FILE *log_file)
{
   char *lstr = xcalloc(FSIC_PATH_MAX);
   int anomalies = 0;

   if (db_file_attr.st_mode != live_file_attr.st_mode)
   {
      sprintf(lstr, "check_file_attributes() <WARNING> File Permissions Anomaly: %s\n", file_path);
      print_log_entry(lstr, log_file);
      anomalies++;
   }

   if (db_file_attr.st_ino != live_file_attr.st_ino)
   {
      sprintf(lstr, "check_file_attributes() <WARNING> Inode Anomaly: %s\n", file_path);
      print_log_entry(lstr, log_file);
      memset(lstr, 0, FSIC_PATH_MAX);
      anomalies++;
   }

   if (db_file_attr.st_uid != live_file_attr.st_uid)
   {
      sprintf(lstr, "check_file_attributes() <WARNING> UID Anomaly: %s\n", file_path);
      print_log_entry(lstr, log_file);
      anomalies++;
   }

   if (db_file_attr.st_gid != live_file_attr.st_gid)
   {
      sprintf(lstr, "check_file_attributes() <WARNING> GID Anomaly: %s\n", file_path);
      print_log_entry(lstr, log_file);
      anomalies++;
   }

   if (db_file_attr.st_size != live_file_attr.st_size)
   {
      sprintf(lstr, "check_file_attributes() <WARNING> File Size Anomaly: %s\n", file_path);
      print_log_entry(lstr, log_file);
      anomalies++;
   }

   if (db_file_attr.st_mtime != live_file_attr.st_mtime)
   {
      sprintf(lstr, "check_file_attributes() <WARNING> File Modification Time Anomaly: %s\n", file_path);
      print_log_entry(lstr, log_file);
      anomalies++;
   }
   xfree(lstr, FSIC_PATH_MAX);

   return anomalies;
}

/*
   Function: parse_file_attributes()
 
   Purpose : Converts db entry stat values to numeric.
   Input   : stat structure and input buffer.
   Output  : stat struct containing the file attributes.
*/
int parse_file_attributes(struct stat *file_attr)
{
   /* file mode and permissions */
   char *token = strtok(NULL, ",");
   file_attr->st_mode = strtol(token, NULL, 0);

   if (token == NULL)
   {
      printf("parse_file_attributes() <ERROR> File mode is null!\n");
      return(1);
   }

   /* inode number */
   token = strtok(NULL, ",");
   file_attr->st_ino = strtol(token, NULL, 0);

   if (token == NULL)
   {
      printf("parse_file_attributes() <ERROR> File mode is null!\n");
      return(1);
   }

   /* file size */
   token = strtok(NULL, ",");
   file_attr->st_size = strtol(token, NULL, 0);

   if (token == NULL)
   {
      printf("parse_file_attributes() <ERROR> File mode is null!\n");
      return(1);
   }

   /* last modification data */
   token = strtok(NULL, ",");
   file_attr->st_mtime = strtol(token, NULL, 0);

   if (token == NULL)
   {
      printf("parse_file_attributes() <ERROR> File mode is null!\n");
      return(1);
   }

   /* file owner */
   token = strtok(NULL, ",");
   file_attr->st_uid = strtol(token, NULL, 0);

   if (token == NULL)
   {
      printf("parse_file_attributes() <ERROR> File mode is null!\n");
      return(1);
   }

   /* file group */
   token = strtok(NULL, ",");
   file_attr->st_gid = strtol(token, NULL, 0);

   if (token == NULL)
   {
      printf("parse_file_attributes() <ERROR> File mode is null!\n");
      return(1);
   }

   return(0);
}

/*
   Function: validate_db_line()
 
   Purpose : Checks the input file path for invalid characters, shell codes and other anomalies.
   Input   : Log file, database entry string.
   Output  : Returns 0 if Ok or 1 if an anomaly is detected.
*/
int validate_db_line(char *db_entry, FILE *log_file)
{
   int i;

   if ((db_entry == NULL) || (strlen(db_entry) == 0) || (strlen(db_entry) > DB_LINE_MAX) || (log_file == NULL))
   {
      printf("validate_db_line() <ERROR> Invalid Parameters.\n");
      return(1);
   }

   char *lstr = xcalloc(DB_LINE_MAX + 100);

   if (db_entry[0] != '/')
   {
      sprintf(lstr, "validate_db_line() <ERROR> Not an absolute path!: %s\n", db_entry);
      print_log_entry(lstr, log_file);
      xfree(lstr, DB_LINE_MAX + 100);
      return(1);
   }
      
   for (i = 0; i < strlen(db_entry) - 1; i++)
   {
      if ((db_entry[i] < 32) || (db_entry[i] > 126)) /* not a printable character !(isascii() and isprint()) */
      {
         sprintf(lstr, "validate_db_line() <ERROR> Invalid characters in database entry!: %s\n", db_entry);
         print_log_entry(lstr, log_file);
         xfree(lstr, DB_LINE_MAX + 100);
         return(1);
      }
   }
   
   i = strcspn(db_entry, ",");

   if ((i > 0) && (i < strlen(db_entry)))
   {
      char *file_path = xcalloc(FSIC_PATH_MAX);
      strncpy(file_path, db_entry, i);
      struct stat fstat;
      if (stat(file_path, &fstat) != 0)
      {
         sprintf(lstr, "validate_db_line() <ERROR> Invalid file in database entry!: %s\n", db_entry);
         print_log_entry(lstr, log_file);
         xfree(lstr, DB_LINE_MAX + 100);
         return(1);
      }

      xfree(file_path, FSIC_PATH_MAX);
   }
   else
   {
      sprintf(lstr, "validate_db_line() <ERROR> Invalid database entry!: %s\n", db_entry);
      print_log_entry(lstr, log_file);
      xfree(lstr, DB_LINE_MAX + 100);
      return(1);  
   }

   xfree(lstr, DB_LINE_MAX + 100);

   return(0);
}


