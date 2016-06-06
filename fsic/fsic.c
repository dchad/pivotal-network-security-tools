/*
   fsic.c

   Title : File System Integrity Checker
   Author: Derek Chadwick
   Date  : 24/09/2011
  
   Purpose: FSIC Main.
   
*/
 
#include <mhash.h>
#include <stdio.h>
#include <stdlib.h>

#include "fsic.h"


int main(int argc, char *argv[])
{
   FILE *log_file = open_log_file(argv[0]);

   if (log_file == NULL)
   {
      printf("main() <ERROR> Could not open log file.\n");
      exit(FILE_ERROR);
   }
   print_log_entry("main() <INFO> Starting FSIC 1.0\n", log_file);

   int mode = parse_command_line_args(argc, argv, log_file);

   switch (mode)
   {
      case UPDATE   : if (update_database(log_file) == 0) 
                         update_self_test_database(log_file); break;
      case CHECK    : check_files(log_file); break;
      case PASSWORD : change_password(log_file); break;
      case SELF_TEST: self_test(log_file); break;
      default :
         print_log_entry("main() <ERROR> Invalid command line options!\n", log_file);
         print_help();
   }
    
   fclose(log_file);

   exit(0);
}

/*
   Function: parse_command_line_args
   Purpose : Validates the run mode option.
   Input   : argc, argv
   Return  : Run Mode
*/
int parse_command_line_args(int argc, char *argv[], FILE *log_file)
{
   int retval = 0;

   if (argc == 2)
   {
      if (strncmp(argv[1], "-p", 2) == 0)
      {
         retval = PASSWORD;
      }
      else if (strncmp(argv[1], "-u", 2) == 0)
      {
         retval = UPDATE;
      }
      else if (strncmp(argv[1], "-c", 2) == 0)
      {
         retval = CHECK;
      }
      else if (strncmp(argv[1], "-s", 2) == 0)
      {
         retval = SELF_TEST;
      }
      else
      {
         print_log_entry("parse_command_line_args() <ERROR> Invalid Option.\n", log_file);
      }
 
   }
   else
   {
      print_log_entry("parse_command_line_args() <ERROR> Incorrect Options.\n", log_file);
   }
   return(retval);
}


