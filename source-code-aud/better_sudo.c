/*
 * better_sudo.c
 * this is a suid binary; a replacement for sudo
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <errno.h>

#define CONF_PATH_VALID_SUDOERS "/opt/better_sudo/etc/valid_sudoers"
#define CONF_PATH_AUDITLOG "/var/log/better_sudo.log"
#define CONF_PASSWORD_FILE "/opt/better_sudo/etc/password"

void get_password(char* password);
bool check_password(char* password);
bool valid_sudoer(void);
void _log(int level, char* message);
void setup_logging(void);
void parse_options(int argc, char* argv[]);
static char* get_username(void);
char* build_arg_str(char* argstr);
FILE* auditlog;

struct _options {
	char prog_name[512];
	bool verbose;
	int uid;
	int gid;
	char* command;
	char** arguments;
} options = {0};

int main(int argc, char* argv[]) {
  	char password[512];
	char tmp[512];

	parse_options(argc, argv);

	if(getuid() == geteuid() && getuid() != 0) {
		fprintf(stderr,"better_sudo needs to be a suid to work!\n");
		exit(EXIT_FAILURE);
	}
	setup_logging();
	if(options.verbose) {
		fprintf(stderr,"uid: %u, euid: %u\n",getuid(),geteuid());
	}

	/* only check password if we're trying to sudo to someone who isn't us */
	if(getuid() != options.uid && getgid() != options.gid) 
	{
			if(!valid_sudoer())
			{
				fprintf(stderr, "%s is not in the sudoers file.  This incident has been reported...\n",get_username());
				_log(LOG_ALERT,strcat(get_username()," is not in the sudoers file"));
				return EXIT_FAILURE;
			}

			get_password(password);
			if(!check_password(password)) {
				fprintf(stderr,"invalid password\n");
				_log(LOG_ALERT,"failed authentication");
				return EXIT_FAILURE;
			}
	}
	if(options.verbose) {
		fprintf(stderr,"executing %s with uid:%u and gid:%u and arguments ",options.command,options.uid,options.gid);
		char arg_str[512] = {0};
		build_arg_str(arg_str);
		fprintf(stderr,arg_str);
	}
	snprintf(tmp,sizeof tmp,"executing command %s",options.command);
	_log(LOG_NOTICE,tmp);

	seteuid(options.uid);
	setegid(options.gid);
	setuid(options.uid);
	setgid(options.gid);
	
	if(execvp(options.command,options.arguments) < 0) {
		fprintf(stderr,"%s\n",strerror(errno));	
		return EXIT_FAILURE;
	}
}

char* build_arg_str(char* arg_str) {
	char **argv = options.arguments;
	arg_str[0] = '[';
	arg_str[1] = '\0';
	while(*argv != NULL) {
		strncat(arg_str,*argv,511);
		strncat(arg_str,",",511);
		argv++;
	}
	arg_str[strlen(arg_str)-1] = ']';
	return arg_str;
}

void print_help(void) {
	fprintf(stderr,"usage: %s (-u <uid>) (-g <gid>) -- <command> <arguments>\n",options.prog_name);
	exit(EXIT_FAILURE);
}

void parse_options(int argc, char* argv[]) {
	strcpy(options.prog_name,argv[0]);
	int last_flag = 0;
	for(int i=1;i<argc; ++i) {
		if(argv[i][0] == '-') {
			last_flag = i; 
			for(int j=1;j<strlen(argv[i]);++j) {
				switch(argv[i][j]) {
					case 'h':
						print_help();
					case 'u':
						options.uid = atoi(argv[i+1]);
						last_flag++;
						break;
					case 'g':
						options.gid = atoi(argv[i+1]);
						last_flag++;
						break;
					case 'v':
						options.verbose = true;
						break;
					case '-':
						goto loop_break;
					default:
						fprintf(stderr,"unknown flag '%c'\n",argv[i][j]);
						exit(EXIT_FAILURE);
				}
			}
		}
	}
loop_break:
	if(argc-1 < last_flag+1) {
		print_help();
	}
	options.command = argv[last_flag+1];
	options.arguments = &argv[last_flag+1];
}
static char* get_username(void) {
	static char username[512];
	system("logname > /tmp/better_sudo.tmp");
	FILE* f = fopen("/tmp/better_sudo.tmp","r");
	fgets(username,sizeof username,f);
	*strchr(username,'\n') = '\0';
	return username;
}

void setup_logging(void) {
	openlog("better_sudo",0,LOG_AUTH);
	auditlog = fopen(CONF_PATH_AUDITLOG,"a");
	if(!auditlog) {
		fprintf(stderr,"unable to open logfile\n");
		exit(EXIT_FAILURE);
	}
}

void _log(int level, char* message) {
	char tmp[512];
	sprintf(tmp,"%s: %s\n",get_username(),message);
	fwrite(tmp,strlen(tmp), 1, auditlog);
	/* log both to the system log and to our own logfile */
	syslog(level, message);
}

void get_password(char* password) {
	fprintf(stderr,"enter password:\n");
	fgets(password, sizeof password, stdin);
	password[strlen(password)-1] = '\0';
}

bool check_password(char* password) {

	FILE* password_file = fopen(CONF_PASSWORD_FILE,"r");
	if(!password_file) {
		fprintf(stderr,"unable to open password file");
	}
	char sudo_password[512];
	fgets(sudo_password,sizeof sudo_password, password_file);

	/* prevent timing attacks */
	bool valid_match = true;
	int characters = strlen(password);
	for(int i=0;i<characters;++i) {
		if(password[i] != sudo_password[i]) {
			valid_match = false;
		}
	}

	return valid_match;
}
bool valid_sudoer(void) {
	char line[512];
	char* username = get_username();
	FILE* sudoers = fopen(CONF_PATH_VALID_SUDOERS,"r");
	while(fgets(line, sizeof line, sudoers)) {
			for(int i=0;i<=strlen(line);++i) {
				if(line[i] == '\n') {
					line[i] = '\0';
					break;
				}
			}
			if(!strcmp(username,line)) {
				return true;
			}
	}
	return false;
}
