#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // funkar bättre på macOS istället för crypt.h
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "pwdblib.h"

#define USERNAME_SIZE (32)
#define NOUSER (-1)

// Funktion för att ignorera Ctrl+C
void handle_sigint(int sig) {
    printf("\nInterrupt signal ignored. Please use the correct logout method.\n");
}

// Funktiondeklarationer innan main()
void print_user_info(struct pwdb_passwd *user);
void start_user_shell(struct pwdb_passwd *user);

int authenticate_user(const char *username, struct pwdb_passwd **user_info) {
    struct pwdb_passwd *p = pwdb_getpwnam(username);
    if (p == NULL) {
        return NOUSER;  // Användaren finns inte
    }

    // Om kontot är låst
    if (p->pw_failed >= 3) {
        printf("Account is locked due to multiple failed login attempts.\n");
        return NOUSER;
    }

    char *entered_password = getpass("Password: ");

    if (strcmp(crypt(entered_password, p->pw_passwd), p->pw_passwd) == 0) {
        *user_info = p;
        
        // Återställ misslyckade försök och öka inloggningsåldern
        p->pw_failed = 0;
        p->pw_age++;

        // Uppdatera pwfile
        if (pwdb_update_user(p) != 0) {
            printf("Error updating user data.\n");
        }

        // Påminn om att byta lösenord om `pw_age` är för högt
        if (p->pw_age >= 5) {
            printf("Reminder: You should change your password soon.\n");
        }

        return 0;
    } else {
        // Öka misslyckade försök och spara i pwfile
        p->pw_failed++;
        if (pwdb_update_user(p) != 0) {
            printf("Error updating failed login attempts.\n");
        }
        return NOUSER;
    }
}

void read_username(char *username) {
    printf("login: ");
    fgets(username, USERNAME_SIZE, stdin);
    username[strcspn(username, "\n")] = '\0';

    // Möjlighet att avsluta programmet med "exit"
    if (strcmp(username, "exit") == 0) {
        printf("Exiting program.\n");
        exit(0);
    }
}

// Funktion för att starta användarens terminal
void start_user_shell(struct pwdb_passwd *user) {
    pid_t pid = fork();

    if (pid == 0) {  // Barnprocessen
        // Sätt UID och GID till användarens värden från pwfile
        if (setgid(user->pw_gid) != 0 || setegid(user->pw_gid) != 0) {
            perror("Failed to set GID");
            _exit(1);
        }
        if (setuid(user->pw_uid) != 0 || seteuid(user->pw_uid) != 0) {
            perror("Failed to set UID");
            _exit(1);
        }

        // Starta en ny xterm med användarens shell
        execl("/usr/bin/xterm", "xterm", "-e", user->pw_shell, NULL);

        // Om execl misslyckas
        perror("execl failed");
        _exit(1);
    } else if (pid > 0) {  // Föräldraprocessen
        waitpid(pid, NULL, 0);  // Vänta på att terminalen stängs
    } else {
        perror("fork failed");
    }
}

void print_user_info(struct pwdb_passwd *user) {
    printf("\n=== User Information ===\n");
    printf("Name: %s\n", user->pw_name);
    printf("Uid: %u\n", user->pw_uid);
    printf("Gid: %u\n", user->pw_gid);
    printf("Real name: %s\n", user->pw_gecos);
    printf("Home dir: %s\n", user->pw_dir);
    printf("Shell: %s\n", user->pw_shell);
    printf("========================\n\n");
}

int main() {
    char username[USERNAME_SIZE];
    struct pwdb_passwd *user_info = NULL;

    // Ignorera Ctrl+C
    signal(SIGINT, handle_sigint);

    while (1) { 
        read_username(username);

        if (authenticate_user(username, &user_info) == 0) {
            printf("User authenticated successfully\n");
            print_user_info(user_info);
            start_user_shell(user_info);  // Starta användarens terminal efter inloggning
        } else {
            printf("Unknown user or incorrect password.\n\n");
        }
    }

    return 0;
}
