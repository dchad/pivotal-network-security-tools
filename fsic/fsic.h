/*
   fsic.h

   Title : File System Integrity Checker ICT539 Semester 2 Project
   Author: Derek Chadwick 18910502
   Date  : 24/09/2011
  
   Purpose: FSIC global definitions.
   
*/

#include <sys/stat.h>

/*
   Constant Definitions
*/

#define CONFIG_FILE "./fsic.conf"
#define DATABASE_FILE "./fsic.db"
#define PASSWORD_FILE "./fsic.pw"
#define SELF_CHECK_FILE "./fsic.sc"
#define LOG_FILE "./fsic.log"
#define BINARY_FILE "./fsic"
#define FSIC_PATH_MAX 4096 /* Redefine max path length since limits.h does weird things! */
#define BACKSPACE 8
#define HASH_MAX 256
#define DB_LINE_MAX 4096
#define DEBUG 0

/*
   REGEXs
*/

#define BEST_REGEX "/^.*(?=.{6,})(?=.*[A-Z])(?=.*[\d])(?=.*[\W]).*$/"

#define STRONG_REGEX "/^[a-zA-Z\d\W_]*(?=[a-zA-Z\d\W_]{6,})(((?=[a-zA-Z\d\W_]*[A-Z])(?=[a-zA-Z\d\W_]*[\d]))|((?=[a-zA-Z\d\W_]*[A-Z])(?=[a-zA-Z\d\W_]*[\W_]))|((?=[a-zA-Z\d\W_]*[\d])(?=[a-zA-Z\d\W_]*[\W_])))[a-zA-Z\d\W_]*$/"

#define WEAK_REGEX "/^[a-zA-Z\d\W_]*(?=[a-zA-Z\d\W_]{6,})(?=[a-zA-Z\d\W_]*[A-Z]|[a-zA-Z\d\W_]*[\d]|[a-zA-Z\d\W_]*[\W_])[a-zA-Z\d\W_]*$/"

#define BAD_REGEX "/^((^[a-z]{6,}$)|(^[A-Z]{6,}$)|(^[\\d]{6,}$)|(^[\\W_]{6,}$))$/"

/* 
   COMPILED-IN_KEY
*/

#ifndef KEY1
#define KEY1 "4300da90c4401052a8efae996119725"
#endif

/*
   ENUMs
*/

enum op_modes { UPDATE = 1, CHECK, PASSWORD, SELF_TEST };
enum error_codes { SUCCESS, INVALID_PASSWORD, FILE_ERROR, INTEGRITY_ERROR, MALLOC_ERROR, SYSTEM_ERROR, UNKNOWN_ANOMALY, INVALID_HMAC, WEAK_PASSWORD };
enum pw_length { MIN_PW_LEN = 8, MAX_PW_LEN = 255 };
enum log_modes { LOG_ERROR, LOG_WARNING, LOG_INFO };

/*
   Function Prototypes
*/

/* util.c */
int fatal(char *str);
void *xcalloc (size_t size);
void *xmalloc (size_t size);
void *xrealloc (void *ptr, size_t size);
int xfree(char *buf, int len);
int print_help();
char* xitoa(int value, char* result, int len, int base);

/* password.c */
int get_password(char *pw, int len, int prompt);
int authenticate_user(FILE *log_file);
int change_password(FILE *log_file);
int update_password_file(char *hmac, FILE *log_file);
int evaluate_password(char *pw);
int match(const char *string, char *pattern);

/* fsic.c */
int parse_command_line_args(int argc, char *argv[], FILE *log_file);

/* update.c */
int update_database(FILE *log_file);
int validate_db_line(char *db_entry, FILE *log_file);
int validate_file_path(char *fpath, FILE *log_file);
int convert_file_attributes(const struct stat file_attr, char *outbuf);

/* self.c */
int self_test(FILE *log_file);
int update_self_test_database(FILE *log_file);

/* check.c */
int check_files(FILE *log_file);
int parse_file_attributes(struct stat *file_attr);
int check_file_attributes(const struct stat db_file_attr, const struct stat live_file_attr, char *file_path, FILE *log_file);
int validate_files(FILE *db_file, FILE *log_file);

/* log.c */
FILE *open_log_file(char *startup_path);
int print_log_entry(char *estr, FILE *log_file);

/* hmac.c */
int generate_password_hmac(char *pw, char *hmac);
int generate_file_hmac(char *hmac, FILE *target_file, unsigned long file_size, FILE *log_file);
int get_password_hmac(char *pw, char *hmac, char *salt);



/* Unit Test Functions */
int unit_tests(FILE *log_file);
int stuff_password_file();



