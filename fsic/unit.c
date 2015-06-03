/*
   unit.c

   Title : File System Integrity Checker ICT539 Semester 2 Project
   Author: Derek Chadwick 18910502
   Date  : 24/09/2011
  
   Purpose: FSIC Unit Tests for input validation and boundary conditions.
   
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fsic.h"

#define password_ut(value, result, tnum) do { if (evaluate_password(value) == result) printf("%s: PASS\n", tnum); else printf("%s: FAIL\n", tnum); tests_run++; } while (0)

#define file_hmac_ut(hmac, target, size, log, result, tnum) do { if (generate_file_hmac(hmac, target, size, log) == result) printf("%s: PASS\n", tnum); else printf("%s: FAIL\n", tnum); tests_run++; } while (0)

#define gen_hmac_ut(pw, hmac, result, tnum) do { if (generate_password_hmac(pw, hmac) == result) printf("%s: PASS\n", tnum); else printf("%s: FAIL\n", tnum); tests_run++; } while (0)

#define get_pw_hmac_ut(pw, hmac, salt, result, tnum) do { if (get_password_hmac(pw, hmac, salt) == result) printf("%s: PASS\n", tnum); else printf("%s: FAIL\n", tnum); tests_run++; } while (0)

#define validate_path_ut(path, log, result, tnum) do { if (validate_file_path(path, log) == result) printf("%s: PASS\n", tnum); else printf("%s: FAIL\n", tnum); tests_run++; } while (0)

#define validate_db_line_ut(entry, log, result, tnum) do { if (validate_db_line(entry, log) == result) printf("%s: PASS\n", tnum); else printf("%s: FAIL\n", tnum); tests_run++; } while (0)

int main(int argc, char *argv[])
{
   int tests_run = 0;
   char *pw = xcalloc(MAX_PW_LEN);
   char *hmac = xcalloc(HASH_MAX);
   char *salt = xcalloc(HASH_MAX);
   char *file_path = xcalloc(FSIC_PATH_MAX);
   char *big_str = xcalloc(FSIC_PATH_MAX * 2);
   FILE *target_file = fopen("./fsic.db", "r");
   FILE *log_file = open_log_file(argv[0]);
   int i;

   if (log_file == NULL)
   {
      printf("main() <ERROR> Could not open log file.\n");
      exit(FILE_ERROR);
   }
   print_log_entry("main() <INFO> Starting Unit Tests...\n", log_file);

   /* Test function for generating new password HMAC and writing to the password file */ 
   stuff_password_file();

   for (i = 0; i < (FSIC_PATH_MAX * 2); i++)
   {
      big_str[i] = '\x90'; /* simulate a NOP sled */
   }

   printf("main() Compiled-In-Key = %s\n", KEY1);

   /* Password Tests */
   password_ut("1234567", WEAK_PASSWORD, "UTP1");
   password_ut("12345678", WEAK_PASSWORD, "UTP2");
   password_ut("123456789", WEAK_PASSWORD, "UTP3");
   password_ut("a", WEAK_PASSWORD, "UTP4");
   password_ut("aaaaaaaaa", WEAK_PASSWORD, "UTP5");
   password_ut("AAAAAAAAA", WEAK_PASSWORD, "UTP6");
   password_ut("1234567Aa", SUCCESS, "UTP7");
   password_ut("aaaaaaaA1", SUCCESS, "UTP8");
   password_ut(NULL, INVALID_PASSWORD, "UTP9");
   password_ut("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",WEAK_PASSWORD,"UTP10");
   password_ut("\x90\x1F\x80", INVALID_PASSWORD, "UTP11");
   password_ut(big_str, INVALID_PASSWORD, "UTP12");

   /* HMAC tests */
   file_hmac_ut(0, 0, 0, log_file, 1, "UTH1"); 
   file_hmac_ut(hmac, target_file, 0, log_file, 1, "UTH2"); 
   file_hmac_ut(hmac, target_file, 100, log_file, 0, "UTH3");
   gen_hmac_ut(pw, hmac, 0, "UTH4");
   gen_hmac_ut(NULL, hmac, 1, "UTH5");
   gen_hmac_ut(pw, NULL, 1, "UTH6"); 
   gen_hmac_ut(NULL, NULL, 1, "UTH7");
   get_pw_hmac_ut(pw, hmac, salt, 1, "UTH8");
   get_pw_hmac_ut(NULL, hmac, salt, 1, "UTH9");
   get_pw_hmac_ut(pw, NULL, salt, 1, "UTH10");
   get_pw_hmac_ut(pw, hmac, NULL, 1, "UTH11");   
   get_pw_hmac_ut(NULL, NULL, NULL, 1, "UTH12");      

   /* File Path Validation Tests */
   validate_path_ut(NULL, NULL, 1, "UTU1");
   validate_path_ut(NULL, log_file, 1, "UTU2");
   validate_path_ut(file_path, log_file, 1, "UTU3");
   validate_path_ut("./somefile", log_file, 1, "UTU4");
   validate_path_ut("asdf;lkjasdf\n", log_file, 1, "UTU5");
   validate_path_ut("*[]----0x", log_file, 1, "UTU6");
   validate_path_ut("/etc/passwd", log_file, 0, "UTU7");
   validate_path_ut("/\t\n", log_file, 1, "UTU8");
   validate_path_ut("/\x90\x90\x90\x90", log_file, 1, "UTU9");
   validate_path_ut("/\x90xyz..", log_file, 1, "UTU10");
   validate_path_ut(big_str, log_file, 1, "UTU11");
   validate_path_ut("/123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890 \
                123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890 \
                123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\x90", \
                log_file, 1, "UTU12");

   /* Database Entry Validation Tests */
   validate_db_line_ut(NULL, NULL, 1, "UTC1");
   validate_db_line_ut(NULL, log_file, 1, "UTC2");
   validate_db_line_ut("/somefile", log_file, 1, "UTC3");
   validate_db_line_ut("./somefile", log_file, 1, "UTC4");
   validate_db_line_ut("asdf;lkjasdf\n", log_file, 1, "UTC5");
   validate_db_line_ut("/*[]----0x,1234,1234,asdf,1234,0", log_file, 1, "UTC6");
   validate_db_line_ut("/etc/passwd", log_file, 1, "UTC7");
   validate_db_line_ut("/\t\n,\t\n,\t\n", log_file, 1, "UTC8");
   validate_db_line_ut("/\x90\x90\x90\x90,\x90,\x90,", log_file, 1, "UTC9");
   validate_db_line_ut("/\x90,a,b,c,d,e,xyz..", log_file, 1, "UTC10");
   validate_db_line_ut(big_str, log_file, 1, "UTC11");
   validate_db_line_ut("/etc/passwd,33188,1049552,1885,1315720309,0,0, \
                        0x249f4832a0b23d521995a85ba49ded48afd6cc8a74b9dcadf642c44befea69c56 \
                        4e64343245fe37df87e96d558c5de4040caf179795cf7033a4d41cbb9e4447c", log_file, 0, "UTC12");

   /* File Check Test */

   check_files(log_file);

   /* Self-Check Test */

   self_test(log_file);

   print_log_entry("main() <INFO> Finished Unit Tests...\n", log_file);

   fclose(log_file);

   exit(0);
}

/*
   Testing Only.
*/
int stuff_password_file()
{
   char *hmac = xcalloc(256);
   generate_password_hmac("madpenguin", hmac);

   FILE *pwfile = fopen("./fsic.pw", "w");

   fputs(hmac, pwfile);

   xfree(hmac, 256);

   fclose(pwfile);

   return(0);

}




