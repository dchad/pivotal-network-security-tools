/*
   password.c

   Title : File System Integrity Checker
   Author: Derek Chadwick
   Date  : 24/09/2011
  
   Purpose: FSIC password and authentication functions.
   
*/

#include <mhash.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <regex.h>

#include "fsic.h"

/*
   Function: get_password()
 
   Purpose : Implements password input with character masking. Required because the GNU C lib
           : password() function is not part of the ANSI/ISO standard.
   Input   : Char buffer for the password, maximum password length and the prompt type.
   Return  : 0 on success, 1 for invalid password.
*/
int get_password(char *pw, int len, int prompt)
{
   struct termios orig, now;

   int c, i, done;
        
   setvbuf(stdout, NULL, _IONBF ,0);

   tcgetattr(0, &orig);

   now = orig;
   now.c_lflag &= ~(ISIG|ICANON|ECHO);
   now.c_cc[VMIN] = 1;
   now.c_cc[VTIME] = 2;

   tcsetattr(0, TCSANOW, &now);

   done = 0;
   i = 0;

   if (prompt == 0)
   {
      printf("Enter Password: ");
   }
   else if (prompt == 1)
   {
      printf("Enter New Password: ");
   }
   else if (prompt == 2)
   {
      printf("Re-enter Password: ");
   }

   while(!done) 
   {
      c = getchar();
           
      if ((c == '\n') || (i >= len))
      {
         done = 1;
      }
      else if ((toascii(c) == BACKSPACE) || (toascii(c) == 127)) /* backspace or delete */
      {
         printf("\b");
         printf(" ");
         printf("\b");
         i--;
      }
      else
      {
         printf("*");
         pw[i] = c;
         i++;
      }
      /* else
         printf("%i", c); */
   }
   printf("\n");

   tcsetattr(0, TCSANOW, &orig);

   if (i >= MIN_PW_LEN)
   {
      return(SUCCESS);
   }
   else
   {
      return(INVALID_PASSWORD);
   }
}

/*
   Function: authenticate_user()
 
   Purpose : Gets the password, generates a HMAC for the input then reads the HMAC in
           : the password file and compares them.
   Input   : Log file.
   Return  : Returns 0 for success or an error code.
*/
int authenticate_user(FILE *log_file)
{
   char *pw = xcalloc(MAX_PW_LEN); /* do not need to check this, memops fatal() on fail. */
   char salt[] = "$........";
   char *hmac1 = xcalloc(HASH_MAX);
   char *hmac2 = xcalloc(HASH_MAX);
   FILE *pw_file = fopen(PASSWORD_FILE, "r");

   if (pw_file == NULL)
   {
      print_log_entry("authenticate_user() <ERROR> Could not open password file!\n", log_file);
      return(FILE_ERROR);
   }

   if (fgets(hmac1, HASH_MAX, pw_file) == NULL)
   {
      print_log_entry("authenticate_user() <ERROR> Could not read HMAC!\n", log_file);
      fclose(pw_file);
      return(FILE_ERROR);
   }

   fclose(pw_file);

   strncpy(salt, hmac1, 9);

   if (DEBUG)
   {
      printf("authenticate_user() Salt>>> %s\n", salt);
      printf("authenticate_user() HMAC1>>> %s", hmac1);
   }

   /* Now get the user password, generate the hmac and compare with the hmac in the pw file. */

   if (get_password(pw, HASH_MAX, 0) != SUCCESS)
   {
      print_log_entry("authenticate_user() <ERROR> Get Password Failed!\n", log_file);
      return(INVALID_PASSWORD);
   }

   if (get_password_hmac(pw, hmac2, salt) != SUCCESS)
   {
      print_log_entry("authenticate_user() <ERROR> Could not generate HMAC!\n", log_file);
      return(INVALID_HMAC);
   }

   if (DEBUG)
      printf("authenticate_user() HMAC2>>> %s", hmac2);

   if (strlen(hmac1) != strlen(hmac2))
   {
      print_log_entry("authenticate_user() <ERROR> HMACs are different lengths!\n", log_file);
      return(INVALID_HMAC);
   }

   if (strncmp(hmac1, hmac2, strlen(hmac1)) != 0)
   {
      print_log_entry("authenticate_user() <ERROR> Authentication Failed!\n", log_file);
      return(INVALID_PASSWORD);
   }

   xfree(pw, MAX_PW_LEN);
   xfree(hmac1, HASH_MAX);
   xfree(hmac2, HASH_MAX);

   return(SUCCESS);
}

/*
   Function: change_password()
 
   Purpose : Authenticates the user then prompts twice for the new password and updates
           : the password file with the new HMAC if all is good.
   Input   : Log file.
   Return  : Updates password file on success, otherwise returns an error code.
*/
int change_password(FILE *log_file)
{
   char *password1 = xcalloc(HASH_MAX); /* do not need to check this, memops fatal() on fail. */
   char *password2 = xcalloc(HASH_MAX);
   char *hmac = xcalloc(HASH_MAX);

   if (authenticate_user(log_file) != SUCCESS)
   {
      print_log_entry("change_password() <ERROR> Authentication Failed!\n", log_file);
      return(1);
   }

   int done = 0;
   while (done == 0)
   {
      if (get_password(password1, HASH_MAX, 1) != 0)
      {
         print_log_entry("change_password() <ERROR> Get Password Failed!\n", log_file);
         return(INVALID_PASSWORD);
      }
      int res = evaluate_password(password1);
      if (res == SUCCESS)
      {
         done = 1;
      }
      else if (res == WEAK_PASSWORD)
      {
         printf("Password is too weak, try again...\n"); /* MadPenguin99 */
      }
      else
      {
         printf("Invalid password, try again...\n");
      }
   }

   if (get_password(password2, HASH_MAX, 2) != 0)
   {
      print_log_entry("change_password() <ERROR> Get Password Failed2!\n", log_file);
      return(INVALID_PASSWORD);
   }   

   /* now compare the passwords */
   if (DEBUG)
      printf("Password>>> %s\n", password1);

   if ((strlen(password1) != strlen(password2)) || (strncmp(password1, password2, strlen(password1)) != 0))
   {
      print_log_entry("change_password() <ERROR> Get Password Failed!\n", log_file);
      return(INVALID_PASSWORD);      
   } 

   /* generate the new hmac and update the password file */

   if (generate_password_hmac(password1, hmac) != SUCCESS)
   {
      print_log_entry("change_password() <ERROR> HMAC Generation Failed!\n", log_file);
      return(INVALID_PASSWORD);            
   }
 
   if (update_password_file(hmac, log_file) == 0)
   {
      print_log_entry("change_password() <INFO> Changed Password!\n", log_file);
   }
   else
   {
      print_log_entry("change_password() <ERROR> Password Update Failed!\n", log_file);
   }

   xfree(password1, HASH_MAX);
   xfree(password2, HASH_MAX);
   xfree(hmac, HASH_MAX);

   return(SUCCESS);
}

/*
   Function: update_password_file()
 
   Purpose : Writes the new password HMAC to the password file.
           : 
   Input   : HMAC string and log file.
   Return  : 0 on success, otherwise an error code.
*/
int update_password_file(char *hmac, FILE *log_file)
{

   FILE *pwfile = fopen(PASSWORD_FILE, "w");

   if (pwfile == NULL)
   {
      print_log_entry("update_password_file() <ERROR> Failed to open password file for update!\n", log_file);
      return(FILE_ERROR);
   }

   if (fputs(hmac, pwfile) == EOF)
   {
      print_log_entry("update_password_file() <ERROR> Failed to write hmac to password file!\n", log_file);
   }

   fclose(pwfile);

   return(SUCCESS);

}

/*
   Function: evaluate_password()
 
   Purpose : Checks the password to see if it has at least one upper case and one
           : lower case character and one digit.
   Input   : Char buffer for the password.
   Return  : 0 on success, otherwise an error code.
*/
int evaluate_password(char *pw)
{
   int i;
   int lowcase = 0;
   int uppcase = 0;
   int numbers = 0;
   int ctrlcodes = 0;

   if (pw == NULL)
      return(INVALID_PASSWORD);

   int len = strlen(pw);

   for (i = 0; i < len; i++)
   {
      if (islower(pw[i]))
        lowcase++;
      if (isupper(pw[i]))
        uppcase++;
      if (isdigit(pw[i]))
        numbers++;
      if ((pw[i] < 33) || (pw[i] >= 127)) /* No control codes or extended ascii characters */
        ctrlcodes++;
   }
   
   if (ctrlcodes > 0)
   {
      printf("Control codes not permitted in password!\n");
      return(INVALID_PASSWORD);
   }

   if ((lowcase > 0) && (uppcase > 0) && (numbers > 0) && (len >= MIN_PW_LEN) && (len <= MAX_PW_LEN))
      return(SUCCESS);
 
   return(WEAK_PASSWORD);
}
 



int strengthen_password(char *pw)
{
   return(SUCCESS);
}


int match(const char *string, char *pattern) 
{ 
  int status;
  regex_t re;
 
  if(regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0) 
  { 
    printf("match(): compile failed.\n");
    return 0; 
  }

  status = regexec(&re, string, (size_t)0, NULL, 0);
 
  regfree(&re);
  
  if(status != 0) 
  {
     printf("match(): no match.\n");
     return 0; 
  }
 
  return 1; 
}
 
/* GNU C lib recommended get password function */
     
ssize_t my_getpass (char **lineptr, size_t *n, FILE *stream)
{
       struct termios old, new;
       int nread;
     
       /* Turn echoing off and fail if we can't. */
       if (tcgetattr (fileno (stream), &old) != 0)
         return -1;
       new = old;
       new.c_lflag &= ~ECHO;
       if (tcsetattr (fileno (stream), TCSAFLUSH, &new) != 0)
         return -1;
     
       /* Read the password. */
       nread = getline (lineptr, n, stream);
     
       /* Restore terminal. */
       (void) tcsetattr (fileno (stream), TCSAFLUSH, &old);
     
       return nread;
}


