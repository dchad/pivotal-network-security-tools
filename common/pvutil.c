
/*  Copyright 2014 Derek Chadwick

    This file is part of the Pivotal Computer Network Security Tools.

    Pivotal is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Pivotal is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Pivotal.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
   flutil.c

   Title : Pivotal NST Common Utility Functions.
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose: Wrapper functions for various standard C lib functions to
            make them safer.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

/* Bail Out */
int fatal(const char *str)
{
   printf("%s\n", str);
   exit(1);
}

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

/* help */
int print_help()
{
   printf("\nPivotal NST Sensor 1.0\n\n");
   printf("Command: pivotal-sensor <options>\n\n");
   printf("Output to a fineline event file                   : -w\n");
   printf("Only send events to GUI                           : -s\n");
   printf("Specify fineline output filename                  : -o FILENAME\n");
   printf("Specify IE cache input file                       : -i FILENAME\n");
   printf("Specify a GUI server IP address                   : -a 192.168.1.10\n");
   printf("Specify filter file                               : -f FILENAME\n");
   printf("\n");
   printf("Input and output files are optional. For sending events to the GUI\n");
   printf("-a <IPaddress> is mandatory. Minimal command line is:\n\n");
   printf("C:\\fineline-ie -w -i windows.edb\n\n");
   printf("This will open the Windows search cache and output into the\n");
   printf("default fineline event file: fineline-events-YYYYMMDD-HHMMSS.fle\n");
   printf("An optional file filter list can be included, the default filter\n");
   printf("file is fl-file-filter-list.txt\n");

   return(0);
}

/**
 * Modified version of char* style "itoa" with buffer length check.
 * (Kernighan and Ritchie)
 */

char *xitoa(int value, char* result, int len, int base)
{
   char *ptr;
   char *ptr1;
   char tmp_char;
   int tmp_value;
   int i = 0;

   if ((base < 2) || (base > 36))
   {
	  *result = '\0';
      return (result);
   }

   ptr = result;
   ptr1 = result;

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


/*
   Function: get_time_string()

   Purpose : Gets current date and time in a string (YYMMDD-HHMMSS).
           :
   Input   : String for date and time.
   Output  : Formatted date and time string.
*/
int get_time_string(char *tstr, int slen)
{
   time_t curtime;
   struct tm *loctime;
   int len;

   if ((tstr == NULL) || (slen < 15))
   {
      printf("get_time_string() <ERROR> Invalid string or length.\n");
      return(0);
   }
   /* Get the current time. */

   curtime = time (NULL);
   loctime = localtime (&curtime);
   if ((len = strftime(tstr, slen - 1, "-%Y%m%d-%H%M%S", loctime)) < 1)
   {
      printf("get_time_string() <WARNING> Indeterminate time string: %s\n", tstr);
   }

   return(len);
}


int validate_ipv4_address(char *ipv4_addr)
{
	/* TODO: a regex would be nice = m/\d+\.\d+\.\d+\.\d+/ */
	/* struct sockaddr_in sa;
   int result = inet_pton(AF_INET, ipv4_addr, &(sa.sin_addr));
   */

	return(0);
}

int validate_ipv6_address(char *ipv6_addr)
{
	/* TODO: definitely need a regex for this one */
   /* struct sockaddr_in sa;
   int result = inet_pton(AF_INET6, ipv6_addr, &(sa.sin6_addr));
   */

	return(0);
}

int get_ip_address(char *interface, char *ip_addr)
{
   struct ifaddrs *if_addr_s = NULL;
   struct ifaddrs *ifap      = NULL;
   void *tmp_addr_ptr        = NULL;

   if (getifaddrs(&if_addr_s) < 0)
   {
      fatal("get_ip_address() <FATAL> Could not get IP address!!!");
   }

   for (ifap = if_addr_s; ifap != NULL; ifap = ifap->ifa_next)
   {
      if (ifap->ifa_addr->sa_family == AF_INET)
      {
         tmp_addr_ptr=&((struct sockaddr_in *)ifap->ifa_addr)->sin_addr;
         char addr_buffer[INET_ADDRSTRLEN];
         inet_ntop(AF_INET, tmp_addr_ptr, addr_buffer, INET_ADDRSTRLEN);
         printf("get_ip_address() Interface: %s IP Address: %s\n", ifap->ifa_name, addr_buffer);
         if (strncmp(interface, ifap->ifa_name, strlen(interface)) == 0)
         {
            strncpy(ip_addr, addr_buffer, strlen(addr_buffer));
         }
      }
      else if (ifap->ifa_addr->sa_family == AF_INET6)
      {
         tmp_addr_ptr=&((struct sockaddr_in6 *)ifap->ifa_addr)->sin6_addr;
         char addr_buffer[INET6_ADDRSTRLEN];
         inet_ntop(AF_INET6, tmp_addr_ptr, addr_buffer, INET6_ADDRSTRLEN);
         printf("get_ip_address() Interface: %s IP Address: %s\n", ifap->ifa_name, addr_buffer);

         /* TODO: add a command line option to specify ipv4 or ipv6 capture,
                  ignore ipv6 during prototyping cycles.
         if (strncmp(interface, ifap->ifa_name, strlen(interface)) == 0)
         {
            strncpy(ip_addr, addr_buffer, strlen(addr_buffer));
         }
         */
      }
   }
   if (if_addr_s != NULL)
      freeifaddrs(if_addr_s);

   return(0);
}

/* DEPRECATED: use above ^ */
int get_ipv4_address(char *ipv4_addr)
{
   FILE *fp = popen("ifconfig", "r");

   if (fp != NULL)
   {
      char *p=NULL, *e;
      size_t n;
      while ((getline(&p, &n, fp) > 0) && p)
      {
         if ((p = strstr(p, "inet ")) != NULL)
         {
            p+=5;
            if ((p = strchr(p, ':')) != NULL)
            {
               ++p;
               if ((e = strchr(p, ' ')) != NULL)
               {
                  *e='\0';
                  printf("%s\n", p);
               }
            }
         }
      }
   }

   pclose(fp);

   return(0);
}

char *ltrim(char *s)
{
   while(isspace(*s)) s++;
   return s;
}

char *rtrim(char *s)
{
   char* back = s + strlen(s);
   while(isspace(*--back));
   *(back+1) = '\0';
   return s;
}

char *trim(char *s)
{
   return rtrim(ltrim(s));
}
