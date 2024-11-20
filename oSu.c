#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <errno.h>
#include <linux/securebits.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <termios.h>
#include <pty.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#include <signal.h>

// Color Definitions
#define GREEN "\033[1;32m"
#define RED "\033[1;31m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[1;34m"
#define MAGENTA "\033[1;35m"
#define CYAN "\033[1;36m"
#define RESET "\033[0m"

#define VERSION "1.1"
#define AUTHOR "Oddbyte (https://oddbyte.dev)"

const char *default_config = "\
# oSu configuration file.\n\
\n\
PATH-SECURE = { /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin } # PATH is automatically set to this upon running.\n\
\n\
# You can use UIDs and GIDs:\n\
user-[0] allow-caps all NOPASSWD\n\
group-[0] allow-caps all NOPASSWD\n\
# You can also use user / group names:\n\
# group-[wheel] allow-caps all\n\
# You can set specific capabilities to allow:\n\
# user-[oddbyte] allow-caps cap_dac_override,cap_chown\n\
# You can also deny certain ones:\n\
# group-[oddbyte] allow-caps all deny-caps cap_sys_admin,cap_bpf\n\
# The override specification should go like this, from most important (overrides lowers) to least important:\n\
\n\
# User Deny\n\
# Primary group deny\n\
# User Allow\n\
# Primary group allow\n\
# Supplemental group deny\n\
# Supplemental group allow\n\
\n\
# Example:\n\
# User oddbyte with group oddbyte and supplemental groups users and wheel runs osu\n\
# The config has user-[oddbyte] allow-caps cap_dac_override,cap_chown and group-[oddbyte] allow-caps all deny-caps cap_sys_admin,cap_bpf and group-[wheel] allow-caps all\n\
# This translates into: allow everything except cap_sys_admin,cap_bpf (group wheel allows all, but the primary group (oddbyte) is denying cap_sys_admin,cap_bpf)\n\
";

uid_t original_uid;
gid_t original_gid;
gid_t *user_supp_gids = NULL;
int num_user_supp_gids = 0;

void get_user_groups(uid_t uid, gid_t **groups, int *num_groups);
int has_option(char opt, int argc, char *argv[]);

typedef struct cap_rule {
    int is_user_rule;
    char *name;
    uid_t uid;
    gid_t gid;
    int nopasswd;
    int allow_all_caps;
    int deny_all_caps;
    cap_value_t allow_caps[64];
    int num_allow_caps;
    cap_value_t deny_caps[64];
    int num_deny_caps;
    struct cap_rule *next;
} cap_rule_t;

typedef struct {
    char *path_secure;
    cap_rule_t *rules;
} config_t;

// Function Declarations
void debug_capabilities(const char *message);
void set_all_caps();
void print_usage(int color_enabled);
int authenticate_user(const char *username);
void create_default_config(const char *config_path);
void enforce_config_permissions(const char *config_path);
void parse_config(const char *config_path, config_t *config);
void free_config(config_t *config);
void verify_binary_location(int color_enabled);
void set_secure_path(const char *path_secure, int color_enabled, int debug_mode);
void apply_capabilities(config_t *config, uid_t uid, gid_t gid, gid_t *supp_gids, int num_supp_gids);
void get_user_groups(uid_t uid, gid_t **groups, int *num_groups);
void display_user_capabilities(config_t *config, uid_t uid, gid_t gid, gid_t *supp_gids, int num_supp_gids);
char *trim_spaces(const char *str);

void set_cap_dac_read_search() {
    cap_t caps = cap_get_proc();
    if (!caps) {
        perror(RED "cap_get_proc failed" RESET);
        exit(EXIT_FAILURE);
    }
    cap_value_t cap_dac_read_search = CAP_DAC_READ_SEARCH;
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap_dac_read_search, CAP_SET) == -1) {
        perror(RED "Failed to set CAP_DAC_READ_SEARCH" RESET);
        cap_free(caps);
        exit(EXIT_FAILURE);
    }
    if (cap_set_proc(caps) == -1) {
        perror(RED "Failed to apply capabilities to process" RESET);
        cap_free(caps);
        exit(EXIT_FAILURE);
    }
    cap_free(caps);
}

void clear_cap_dac_read_search() {
    cap_t caps = cap_get_proc();
    if (!caps) {
        perror(RED "cap_get_proc failed" RESET);
        exit(EXIT_FAILURE);
    }
    cap_value_t cap_dac_read_search = CAP_DAC_READ_SEARCH;
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap_dac_read_search, CAP_CLEAR) == -1) {
        perror(RED "Failed to clear CAP_DAC_READ_SEARCH" RESET);
        cap_free(caps);
        exit(EXIT_FAILURE);
    }
    if (cap_set_proc(caps) == -1) {
        perror(RED "Failed to apply capabilities to process" RESET);
        cap_free(caps);
        exit(EXIT_FAILURE);
    }
    cap_free(caps);
}

int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit((unsigned char)*str)) {
            return 0;
        }
        str++;
    }
    return 1;
}

void add_supp_group(gid_t **supp_gids, int *num_supp_gids, int *supp_gids_capacity, gid_t new_gid) {

    for (int i = 0; i < *num_supp_gids; i++) {
        if ((*supp_gids)[i] == new_gid) {
            return; // Already present, do not add again
        }
    }
    // Initialize capacity if necessary
    if (*supp_gids_capacity == 0) {
        *supp_gids_capacity = 10; // Initial capacity
        *supp_gids = malloc(*supp_gids_capacity * sizeof(gid_t));
        if (!*supp_gids) {
            perror(RED "Failed to allocate memory for supplemental groups" RESET);
            exit(EXIT_FAILURE);
        }
    }

    // Resize the array if needed
    if (*num_supp_gids >= *supp_gids_capacity) {
        *supp_gids_capacity *= 2;
        gid_t *temp = realloc(*supp_gids, *supp_gids_capacity * sizeof(gid_t));
        if (!temp) {
            perror(RED "Failed to reallocate memory for supplemental groups" RESET);
            free(*supp_gids);
            exit(EXIT_FAILURE);
        }
        *supp_gids = temp;
    }

    // Add the new GID
    (*supp_gids)[(*num_supp_gids)++] = new_gid;
}

void drop_all_caps() {
    cap_t empty_caps = cap_init();
    if (empty_caps == NULL) {
        perror(RED "Failed to initialize empty capabilities" RESET);
        exit(EXIT_FAILURE);
    }

    if (prctl(PR_SET_SECUREBITS, SECBIT_NO_CAP_AMBIENT_RAISE) == -1) {
        perror(RED "Failed to disable ambient capability raising" RESET);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i <= CAP_LAST_CAP; i++) {
        if (prctl(PR_CAPBSET_DROP, i) == -1) {
            perror(RED "Failed to drop capability from bounding set" RESET);
            exit(EXIT_FAILURE);
        }
    }

    if (cap_set_proc(empty_caps) == -1) {
        perror(RED "Failed to drop all capabilities" RESET);
        cap_free(empty_caps);
        exit(EXIT_FAILURE);
    }
    cap_free(empty_caps);
}

void apply_secure_mode() {
    drop_all_caps();

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror(RED "Failed to set no-new-privs" RESET);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    int color_enabled = 1; // Flag to enable/disable colors

    // Check if output is a terminal
    if (!isatty(STDOUT_FILENO)) {
        color_enabled = 0;
    }

    verify_binary_location(color_enabled);

    int preserve_path = 0;
    char *whitelist_env = NULL;
    char *user = NULL;
    char *group = NULL;
    char *supp_groups = NULL;
    int login_shell = 0;
    char *command = NULL;
    int use_current_terminal = 1; // Use current terminal by default
    int session_command = 0;
    char *set_caps = NULL;
    int show_capabilities = 0;
    int debug_mode = 0;

    static struct option long_options[] = {
        {"preserve-path", no_argument, 0, 2},
        {"whitelist-environment", required_argument, 0, 'w'},
        {"user", required_argument, 0, 'u'},
        {"group", required_argument, 0, 'g'},
        {"supp-group", required_argument, 0, 'G'},
        {"login", no_argument, 0, 'l'},
        {"set-caps", required_argument, 0, 3},
        {"command", required_argument, 0, 'c'},
        {"session-command", required_argument, 0, 1},
        {"pty", no_argument, 0, 'P'},
        {"help", no_argument, 0, 'h'},
        {"what-can-i-do", no_argument, 0, 4},
        {"version", no_argument, 0, 'V'},
        {"debug", no_argument, 0, 5},
        {"no-color", no_argument, 0, 6},
        {"drop", no_argument, 0, 7},
        {0, 0, 0, 0}
    };

    int secure_mode = 0;

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "mpw:u:g:G:lc:PhV", long_options, &option_index)) != -1) {
        switch (opt) {
            case 2:
                preserve_path = 1;
                break;
            case 'w':
                whitelist_env = optarg;
                break;
            case 'u':
                user = optarg;
                break;
            case 'g':
                group = optarg;
                break;
            case 'G':
                supp_groups = optarg;
                break;
            case 'l':
                login_shell = 1;
                break;
            case 3:
                set_caps = optarg;
                break;
            case 'c':
                command = optarg;
                break;
            case 'P':
                use_current_terminal = 0; // Use a new pty if --pty is specified
                break;
            case 'h':
                print_usage(color_enabled);
                exit(EXIT_SUCCESS);
            case 'V':
                if (color_enabled) {
                    printf(GREEN "osu version %s\n" RESET, VERSION);
                    printf(MAGENTA "oSu author: %s\n" RESET, AUTHOR);
                } else {
                    printf("osu version %s\n", VERSION);
                    printf("oSu author: %s\n", AUTHOR);
                }
                exit(EXIT_SUCCESS);
            case 1:
                command = optarg;
                session_command = 1;
                break;
            case 4:
                show_capabilities = 1;
                break;
            case 5:
                debug_mode = 1;
                break;
            case 6:
                color_enabled = 0;
                break;
            case 7:
                secure_mode = 1;
                break;
            default:
                print_usage(color_enabled);
                exit(EXIT_FAILURE);
        }
    }

    original_uid = getuid();
    original_gid = getgid();

    if (debug_mode) {
        if (color_enabled) {
            printf(CYAN "Original UID: %d\n" RESET, original_uid);
            printf(CYAN "Original GID: %d\n" RESET, original_gid);
        } else {
            printf("Original UID: %d\n", original_uid);
            printf("Original GID: %d\n", original_gid);
        }
    }

    struct passwd *pw = getpwuid(original_uid);
    if (!pw) {
        fprintf(stderr, RED "Failed to get user info\n" RESET);
        exit(EXIT_FAILURE);
    }
    const char *username = pw->pw_name;

    gid_t *supp_gids = NULL;
    int num_supp_gids = 0;
    int supp_gids_capacity = 0;

    get_user_groups(original_uid, &user_supp_gids, &num_user_supp_gids);


    if (debug_mode) {
        if (color_enabled) {
            printf(YELLOW "=== uname -a ===\n" RESET);
        } else {
            printf("=== uname -a ===\n");
        }
        system("uname -a");
        if (color_enabled) {
            printf(YELLOW "================\n" RESET);
            printf(CYAN "Caller's ID: \n" RESET);
            printf(CYAN "UID: %d, GID: %d\n" RESET, original_uid, original_gid);
        } else {
            printf("================\n");
            printf("Caller's ID: \n");
            printf("UID: %d, GID: %d\n", original_uid, original_gid);
        }
    }

    const char *config_path = "/etc/osu.conf";
    struct stat st;
    if (stat(config_path, &st) != 0) {
        create_default_config(config_path);
    }

    enforce_config_permissions(config_path);

    config_t config;
    memset(&config, 0, sizeof(config_t));
    parse_config(config_path, &config);

    if (!preserve_path) {
        if (config.path_secure) {
            set_secure_path(config.path_secure, color_enabled, debug_mode);
        } else {
            fprintf(stderr, RED "PATH-SECURE not specified in config file\n" RESET);
            exit(EXIT_FAILURE);
        }
    }

    int requires_auth = 1;
    cap_rule_t *rule = config.rules;
    while (rule) {
        if (rule->is_user_rule && rule->uid == original_uid && rule->nopasswd) {
            requires_auth = 0;
            break;
        }
        rule = rule->next;
    }
    if (requires_auth) {
        if (authenticate_user(username) != 0) {
            fprintf(stderr, RED "Authentication failed\n" RESET);
            exit(EXIT_FAILURE);
        }
    }
    if (show_capabilities) {
        apply_capabilities(&config, original_uid, original_gid, user_supp_gids, num_user_supp_gids);
        display_user_capabilities(&config, original_uid, original_gid, user_supp_gids, num_user_supp_gids);
        free_config(&config);
        free(user_supp_gids);
        exit(EXIT_SUCCESS);
    }

    if (prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP) == -1) {
        perror(RED "Failed to set securebits" RESET);
        exit(EXIT_FAILURE);
    }

    if (setgid(0) == -1 || setuid(0) == -1) {
        perror(RED "Failed to set UID/GID to root" RESET);
        exit(EXIT_FAILURE);
    }

    set_all_caps();

    if (debug_mode) {
        debug_capabilities("After setting all capabilities");
    }

    if (prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP) == -1) {
        perror(RED "Failed to set securebits before dropping root" RESET);
        exit(EXIT_FAILURE);
    }

    // Validate that the caller is allowed to switch to the target user/group
    uid_t target_uid = original_uid;
    gid_t target_gid = original_gid;

    if (user) {
        struct passwd *pw_target = getpwnam(user);
        if (!pw_target) {
            fprintf(stderr, RED "User '%s' not found\n" RESET, user);
            exit(EXIT_FAILURE);
        }
        target_uid = pw_target->pw_uid;

        // Check if the caller has permission to switch to the target user
        if (original_uid != 0 && original_uid != target_uid) {
            fprintf(stderr, RED "You do not have permission to switch to user '%s'\n" RESET, user);
            exit(EXIT_FAILURE);
        }
        setenv("HOME", pw_target->pw_dir, 1);
        setenv("LOGNAME", user, 1);
    }

    if (group) {
        struct group *gr = getgrnam(group);
        if (!gr) {
            fprintf(stderr, RED "Group '%s' not found\n" RESET, group);
            exit(EXIT_FAILURE);
        }
        target_gid = gr->gr_gid;

        // Check if the caller has permission to switch to the target group
        if (original_uid != 0 && original_gid != target_gid) {
            fprintf(stderr, RED "You do not have permission to switch to group '%s'\n" RESET, group);
            exit(EXIT_FAILURE);
        }
    }

    if (supp_groups) {
        char *supp_groups_copy = strdup(supp_groups);
        if (!supp_groups_copy) {
            perror(RED "Failed to duplicate supplemental groups string" RESET);
            exit(EXIT_FAILURE);
        }
        char *token = strtok(supp_groups_copy, ",");
        while (token) {
            struct group *gr = getgrnam(token);
            if (!gr) {
                fprintf(stderr, RED "Supplemental group '%s' not found\n" RESET, token);
                free(supp_groups_copy);
                free(supp_gids);
                exit(EXIT_FAILURE);
            }
            // Check if the caller has permission to add supplemental groups
            if (original_uid != 0) {
                int found = 0;
                for (int i = 0; i < num_user_supp_gids; i++) {
                    if (user_supp_gids[i] == gr->gr_gid) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    fprintf(stderr, RED "You do not have permission to add supplemental group '%s'\n" RESET, token);
                    free(supp_groups_copy);
                    free(supp_gids);
                    exit(EXIT_FAILURE);
                }
            }
            // Add the group dynamically
            add_supp_group(&supp_gids, &num_supp_gids, &supp_gids_capacity, gr->gr_gid);
            token = strtok(NULL, ",");
        }
        free(supp_groups_copy);
    } else {
        // Preserve original supplemental groups
        for (int i = 0; i < num_user_supp_gids; i++) {
            add_supp_group(&supp_gids, &num_supp_gids, &supp_gids_capacity, user_supp_gids[i]);
        }
    }

    // Check if the caller has CAP_SETUID and CAP_SETGID
    cap_t current_caps = cap_get_proc();
    if (!current_caps) {
        perror(RED "Failed to get current capabilities" RESET);
        exit(EXIT_FAILURE);
    }
    cap_flag_value_t cap_setuid_value;
    if (cap_get_flag(current_caps, CAP_SETUID, CAP_EFFECTIVE, &cap_setuid_value) == -1) {
        perror(RED "Failed to get CAP_SETUID flag" RESET);
        cap_free(current_caps);
        exit(EXIT_FAILURE);
    }
    cap_flag_value_t cap_setgid_value;
    if (cap_get_flag(current_caps, CAP_SETGID, CAP_EFFECTIVE, &cap_setgid_value) == -1) {
        perror(RED "Failed to get CAP_SETGID flag" RESET);
        cap_free(current_caps);
        exit(EXIT_FAILURE);
    }

    if(debug_mode) {
        if (color_enabled) {
            printf(YELLOW "Attempting to change UID to %d, and GID to %d\n" RESET, target_uid, target_gid);
            printf(YELLOW "With %d supplemental groups\n" RESET, num_supp_gids);
        } else {
            printf("Attempting to change UID to %d, and GID to %d\n", target_uid, target_gid);
            printf("With %d supplemental groups\n", num_supp_gids);
        }
    }

    if (target_uid != original_uid && cap_setuid_value != CAP_SET) {
        fprintf(stderr, RED "You are not allowed to change user (CAP_SETUID denied).\n" RESET);
        cap_free(current_caps);
        exit(EXIT_FAILURE);
    }

    if ((target_gid != original_gid || num_supp_gids != num_user_supp_gids) && cap_setgid_value != CAP_SET) {
        fprintf(stderr, RED "You are not allowed to change group (CAP_SETGID denied).\n" RESET);
        cap_free(current_caps);
        exit(EXIT_FAILURE);
    }

    cap_free(current_caps);

    if (debug_mode) {
        debug_capabilities("Right before setgroups for supplemental groups");
    }

    // Apply supplemental groups
    if (setgroups(num_supp_gids, supp_gids) == -1) {
        perror(RED "Failed to set supplemental groups" RESET);
        free(supp_gids);
        exit(EXIT_FAILURE);
    }

    // Apply GID
    if (setgid(target_gid) == -1) {
        perror(RED "Failed to set GID" RESET);
        exit(EXIT_FAILURE);
    }

    // Apply UID
    if (setuid(target_uid) == -1) {
        perror(RED "Failed to set UID" RESET);
        exit(EXIT_FAILURE);
    }

    if (debug_mode) {
        debug_capabilities("After setting UID and GID");
    }

    if (secure_mode) {
        apply_secure_mode();
    }

    // Only set PATH to the secure path
    if (!preserve_path) {
        if (config.path_secure) {
            set_secure_path(config.path_secure, color_enabled, debug_mode);
        } else {
            fprintf(stderr, RED "PATH-SECURE not specified in config file\n" RESET);
            exit(EXIT_FAILURE);
        }
    }

    // Apply capabilities based on the caller's UID and GIDs
    if (!secure_mode) apply_capabilities(&config, original_uid, original_gid, user_supp_gids, num_user_supp_gids);

    if (debug_mode) {
        debug_capabilities("After applying capabilities based on configuration");
    }

    // Reset signal handlers
    signal(SIGINT, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGTSTP, SIG_DFL);
    signal(SIGTTIN, SIG_DFL);
    signal(SIGTTOU, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);

    // Set the shell process as the leader of a new process group
    if (setpgid(0, 0) == -1) {
        perror(RED "Failed to set process group" RESET);
        exit(EXIT_FAILURE);
    }

    // Take control of the terminal
    if (tcsetpgrp(STDIN_FILENO, getpid()) == -1) {
        perror(RED "Failed to set controlling terminal" RESET);
        exit(EXIT_FAILURE);
    }

    char *shell = "/usr/bin/bash";
    char *shell_args[6];
    int arg_index = 0;

    if (login_shell) {
        shell_args[arg_index++] = "--login";
    }

    shell_args[arg_index++] = "-i"; // Start an interactive shell

    if (set_caps) {
        cap_value_t user_caps[64];
        int num_user_caps = 0;
        char *caps_copy = strdup(set_caps);
        if (!caps_copy) {
            perror(RED "Failed to duplicate set_caps string" RESET);
            exit(EXIT_FAILURE);
        }
        char *token = strtok(caps_copy, ",");
        while (token && num_user_caps < 64) {
            cap_value_t cap;
            if (cap_from_name(token, &cap) == 0) {
                user_caps[num_user_caps++] = cap;
            } else {
                fprintf(stderr, RED "Invalid capability: %s\n" RESET, token);
                exit(EXIT_FAILURE);
            }
            token = strtok(NULL, ",");
        }
        free(caps_copy);

        cap_t allowed_caps = cap_get_proc();
        if (!allowed_caps) {
            perror(RED "Failed to get allowed capabilities" RESET);
            exit(EXIT_FAILURE);
        }
        cap_t desired_caps = cap_init();
        if (!desired_caps) {
            perror(RED "Failed to initialize desired capabilities" RESET);
            cap_free(allowed_caps);
            exit(EXIT_FAILURE);
        }
        for (int i = 0; i < num_user_caps; i++) {
            cap_set_flag(desired_caps, CAP_EFFECTIVE, 1, &user_caps[i], CAP_SET);
            cap_set_flag(desired_caps, CAP_PERMITTED, 1, &user_caps[i], CAP_SET);
            cap_set_flag(desired_caps, CAP_INHERITABLE, 1, &user_caps[i], CAP_SET);
        }
        if (cap_set_proc(desired_caps) == -1) {
            perror(RED "Failed to set desired capabilities" RESET);
            cap_free(allowed_caps);
            cap_free(desired_caps);
            exit(EXIT_FAILURE);
        }
        cap_free(allowed_caps);
        cap_free(desired_caps);

        for (int i = 0; i < num_user_caps; i++) {
            if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, user_caps[i], 0, 0) == -1) {
                perror(RED "Failed to raise capability in ambient set" RESET);
                exit(EXIT_FAILURE);
            }
        }
    }

    if (command) {
        if(debug_mode) {
            if (color_enabled) {
                printf(YELLOW "command = %s\n" RESET, command);
            } else {
                printf("command = %s\n", command);
            }
        }
        shell_args[arg_index++] = "-c";
        shell_args[arg_index++] = command;
    }

    shell_args[arg_index] = NULL;

    if (use_current_terminal) {
        if (debug_mode) {
            char cmd[4096] = {0}; // Initialize buffer with zeros
            size_t cmd_len = 0;
            for (int i = 0; shell_args[i] != NULL; i++) {
                size_t arg_len = strlen(shell_args[i]);
                if (cmd_len + arg_len + 1 >= sizeof(cmd)) { // +1 for space or null terminator
                    fprintf(stderr, RED "Command too long to debug print.\n" RESET);
                    break;
                }
                strcat(cmd, shell_args[i]);
                cmd_len += arg_len;
                if (shell_args[i + 1] != NULL) { // Add space if not the last argument
                    strcat(cmd, " ");
                    cmd_len += 1;
                }
            }
            if (color_enabled) {
                printf(CYAN "Executing: %s %s\n" RESET, shell, cmd);
            } else {
                printf("Executing: %s %s\n", shell, cmd);
            }
        }
        // Directly exec the shell without forking
        execv(shell, shell_args);
        perror(RED "Failed to execute shell" RESET);
        exit(EXIT_FAILURE);
    } else {
        if (debug_mode) {
            char cmd[4096] = {0}; // Initialize buffer with zeros
            size_t cmd_len = 0;
            for (int i = 0; shell_args[i] != NULL; i++) {
                size_t arg_len = strlen(shell_args[i]);
                if (cmd_len + arg_len + 1 >= sizeof(cmd)) { // +1 for space or null terminator
                    fprintf(stderr, RED "Command too long to debug print.\n" RESET);
                    break;
                }
                strcat(cmd, shell_args[i]);
                cmd_len += arg_len;
                if (shell_args[i + 1] != NULL) { // Add space if not the last argument
                    strcat(cmd, " ");
                    cmd_len += 1;
                }
            }
            if (color_enabled) {
                printf(CYAN "Executing: %s\n" RESET, shell, cmd);
            } else {
                printf("Executing: %s\n", shell, cmd);
            }
        }
        // Create a new pseudo-terminal
        int master_fd;
        pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);
        if (pid == -1) {
            perror(RED "Failed to forkpty" RESET);
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            if (session_command) {
                execv(shell, shell_args);
            } else {
                setsid();
                execv(shell, shell_args);
            }
            perror(RED "Failed to execute shell" RESET);
            exit(EXIT_FAILURE);
        } else {
            if (debug_mode) {
                char cmd[4096] = {0}; // Initialize buffer with zeros
                size_t cmd_len = 0;
                for (int i = 0; shell_args[i] != NULL; i++) {
                    size_t arg_len = strlen(shell_args[i]);
                    if (cmd_len + arg_len + 1 >= sizeof(cmd)) { // +1 for space or null terminator
                        fprintf(stderr, RED "Command too long to debug print.\n" RESET);
                        break;
                    }
                    strcat(cmd, shell_args[i]);
                    cmd_len += arg_len;
                    if (shell_args[i + 1] != NULL) { // Add space if not the last argument
                        strcat(cmd, " ");
                        cmd_len += 1;
                    }
                }
                if (color_enabled) {
                    printf(CYAN "Executing: %s\n" RESET, shell, cmd);
                } else {
                    printf("Executing: %s\n", shell, cmd);
                }
            }
            fd_set fds;
            char buf[256];
            ssize_t nread;

            while (1) {
                FD_ZERO(&fds);
                FD_SET(STDIN_FILENO, &fds);
                FD_SET(master_fd, &fds);

                int maxfd = (STDIN_FILENO > master_fd) ? STDIN_FILENO : master_fd;

                int ret = select(maxfd + 1, &fds, NULL, NULL, NULL);
                if (ret == -1) {
                    perror(RED "select failed" RESET);
                    break;
                }

                if (FD_ISSET(STDIN_FILENO, &fds)) {
                    nread = read(STDIN_FILENO, buf, sizeof(buf));
                    if (nread <= 0)
                        break;
                    write(master_fd, buf, nread);
                }

                if (FD_ISSET(master_fd, &fds)) {
                    nread = read(master_fd, buf, sizeof(buf));
                    if (nread <= 0)
                        break;
                    write(STDOUT_FILENO, buf, nread);
                }
            }
            int status;
            waitpid(pid, &status, 0);
        }
    }

    free_config(&config);
    free(user_supp_gids);
    free(supp_gids);

    return EXIT_SUCCESS;
}

void print_usage(int color_enabled) {
    if (color_enabled) {
        printf(MAGENTA "Usage:\n" RESET);
        printf(" osu [options]\n\n");
        printf(MAGENTA "Options:\n" RESET);
        printf(GREEN " --preserve-path" RESET "                     don't reset path to PATH-SECURE\n");
        printf(GREEN " -w, --whitelist-environment <list>" RESET "  don't reset specified variables (If Path is included in this, it is ignored. Use --preserve-path instead.)\n");
        printf("\n");
        printf(GREEN " -u, --user <user>" RESET "                   specify the user\n");
        printf(GREEN " -g, --group <group>" RESET "                 specify the primary group\n");
        printf(GREEN " -G, --supp-group <group>" RESET "            specify a supplemental group\n");
        printf("\n");
        printf(GREEN " -l, --login" RESET "                         make the shell a login shell\n");
        printf(GREEN " --set-caps <list>" RESET "                   only set the specified capabilities (only if you have access to them. Run osu --what-can-i-do to see all capabilities you are allowed to use.)\n");
        printf(GREEN " -c, --command <command>" RESET "             pass a command to the shell with -c\n");
        printf("                                     please make sure to enclose any commands that require spaces in double quotes (\"\")\n");
        printf("                                     also, please escape any double quotes in the command like so: (\\\")\n");
        printf(GREEN " --session-command <command>" RESET "         pass a command to the shell with -c and do not create a new session\n");
        printf(GREEN " -P, --pty" RESET "                           create a new pseudo-terminal\n");
        printf("\n");
        printf(GREEN " --debug" RESET "                             display debug messages all steps of the way\n");
        printf(GREEN " --drop" RESET "                              drop all privs and capabilities, and set no-new-privs\n");
        printf(GREEN " -h, --help" RESET "                          display this help\n");
        printf(GREEN " --what-can-i-do" RESET "                     display what capabilities you can \n");
        printf(GREEN " -V, --version" RESET "                       display version\n");
        printf("\n");
        printf(MAGENTA "Examples:\n" RESET);
        printf(" osu\n");
        printf(" osu -c sh\n");
        printf(" osu --drop\n");
        printf(" osu -u root -g 0 -G users,106 -c \"echo \\\"hello\\\"\"\n");
        printf("\n");
        printf("osu version %s\n", VERSION);
        printf("oSu author: %s\n", AUTHOR);
    } else {
        printf("Usage:\n");
        printf(" osu [options]\n\n");
        printf("Options:\n");
        printf(" --preserve-path                     don't reset path to PATH-SECURE\n");
        printf(" -w, --whitelist-environment <list>  don't reset specified variables (If Path is included in this, it is ignored. Use --preserve-path instead.)\n");
        printf("\n");
        printf(" -u, --user <user>                   specify the user\n");
        printf(" -g, --group <group>                 specify the primary group\n");
        printf(" -G, --supp-group <group>            specify a supplemental group\n");
        printf("\n");
        printf(" -l, --login                         make the shell a login shell\n");
        printf(" --set-caps <list>                   only set the specified capabilities (only if you have access to them. Run osu --what-can-i-do to see all capabilities you are allowed to use.)\n");
        printf(" -c, --command <command>             pass a command to the shell with -c\n");
        printf("                                     please make sure to enclose any commands that require spaces in double quotes (\"\")\n");
        printf("                                     also, please escape any double quotes in the command like so: (\\\")\n");
        printf(" --session-command <command>         pass a command to the shell with -c and do not create a new session\n");
        printf(" -P, --pty                           create a new pseudo-terminal\n");
        printf("\n");
        printf(" --debug                             display debug messages all steps of the way\n");
        printf(" --drop                              drop all privs and capabilities, and set no-new-privs\n");
        printf(" -h, --help                          display this help\n");
        printf(" --what-can-i-do                     display what capabilities you can \n");
        printf(" -V, --version                       display version\n");
        printf("\n");
        printf("Examples:\n");
        printf(" osu\n");
        printf(" osu -c sh\n");
        printf(" osu -u root -g 0 -G users,106 -c \"echo \\\"hello\\\"\"\n");
        printf("\n");
        printf("osu version %s\n", VERSION);
        printf("oSu author: %s\n", AUTHOR);
    }
}

void debug_capabilities(const char *message) {
    printf(YELLOW "\n=== %s ===\n" RESET, message);
    system("/usr/sbin/capsh --print");
}

void verify_binary_location(int color_enabled) {
    char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1) {
        perror(RED "Failed to get executable path" RESET);
        exit(EXIT_FAILURE);
    }
    path[len] = '\0';
    if (strcmp(path, "/usr/local/bin/osu") != 0) {
        if (color_enabled) {
            fprintf(stderr, RED "This binary must be located at /usr/local/bin/osu\n" RESET);
        } else {
            fprintf(stderr, "This binary must be located at /usr/local/bin/osu\n");
        }
        exit(EXIT_FAILURE);
    }
}

void create_default_config(const char *config_path) {
    FILE *file = fopen(config_path, "w");
    if (!file) {
        perror(RED "Failed to create default config file" RESET);
        exit(EXIT_FAILURE);
    }
    fprintf(file, "%s", default_config);
    fclose(file);
    printf(GREEN "Default configuration file created at %s\n" RESET, config_path);
}

void enforce_config_permissions(const char *config_path) {
    struct stat st;
    if (stat(config_path, &st) != 0) {
        perror(RED "Failed to stat config file" RESET);
        exit(EXIT_FAILURE);
    }
    if (st.st_uid != 0 || st.st_gid != 0) {
        if (chown(config_path, 0, 0) != 0) {
            perror(RED "Failed to change ownership of config file" RESET);
            exit(EXIT_FAILURE);
        }
        if (chown(config_path, 0, 0) == 0) {
            if (st.st_uid != 0 || st.st_gid != 0) {
                printf(GREEN "Ownership of config file set to root.\n" RESET);
            }
        }
    }
    if ((st.st_mode & 0777) != 0400) {
        if (chmod(config_path, 0400) != 0) {
            perror(RED "Failed to change permissions of config file" RESET);
            exit(EXIT_FAILURE);
        }
        printf(GREEN "Permissions of config file set to 0400.\n" RESET);
    }
}

void set_secure_path(const char *path_secure, int color_enabled, int debug_mode) {
    if (setenv("PATH", path_secure, 1) != 0) {
        perror(RED "Failed to set secure PATH" RESET);
        exit(EXIT_FAILURE);
    }
    if (debug_mode) {
        if (color_enabled) {
            printf(GREEN "Secure PATH set to: %s\n" RESET, path_secure);
        } else {
            printf("Secure PATH set to: %s\n", path_secure);
        }
    }
}

char *trim_spaces(const char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0)
        return strdup("");

    const char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        end--;
    }

    size_t len = end - str + 1;
    char *trimmed_str = malloc(len + 1);
    if (!trimmed_str) {
        perror(RED "Failed to allocate memory for trimmed string" RESET);
        exit(EXIT_FAILURE);
    }
    strncpy(trimmed_str, str, len);
    trimmed_str[len] = '\0';
    return trimmed_str;
}

void get_user_groups(uid_t uid, gid_t **groups, int *num_groups) {
    struct passwd *pw = getpwuid(uid);
    if (!pw) {
        perror(RED "getpwuid failed" RESET);
        exit(EXIT_FAILURE);
    }

    int ngroups = 0;
    getgrouplist(pw->pw_name, pw->pw_gid, NULL, &ngroups); // First call to get the size

    gid_t *group_list = malloc(ngroups * sizeof(gid_t));
    if (!group_list) {
        perror(RED "Failed to allocate memory for group list" RESET);
        exit(EXIT_FAILURE);
    }

    if (getgrouplist(pw->pw_name, pw->pw_gid, group_list, &ngroups) == -1) {
        perror(RED "getgrouplist failed" RESET);
        free(group_list);
        exit(EXIT_FAILURE);
    }

    *groups = group_list;
    *num_groups = ngroups;
}

void parse_config(const char *config_path, config_t *config) {
    set_cap_dac_read_search(); // Allow the process to read the config
    FILE *file = fopen(config_path, "r");
    if (!file) {
        perror(RED "Failed to open config file" RESET);
        exit(EXIT_FAILURE);
    }

    clear_cap_dac_read_search(); // Drop privs

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        char *line_copy = strdup(line);
        if (!line_copy) {
            perror(RED "Failed to duplicate line" RESET);
            exit(EXIT_FAILURE);
        }

        if (line_copy[0] == '#') {
            free(line_copy);
            continue;
        }

        char *comment = strchr(line_copy, '#');
        if (comment) {
            *comment = '\0';
        }

        char *trimmed_line = line_copy;
        while (isspace((unsigned char)*trimmed_line)) {
            trimmed_line++;
        }

        char *end = trimmed_line + strlen(trimmed_line) - 1;
        while (end > trimmed_line && isspace((unsigned char)*end)) {
            *end = '\0';
            end--;
        }

        if (strlen(trimmed_line) == 0) {
            free(line_copy);
            continue;
        }

        if (strncmp(trimmed_line, "PATH-SECURE", 11) == 0) {
            char *start = strchr(trimmed_line, '{');
            char *end_brace = strchr(trimmed_line, '}');
            if (start && end_brace && end_brace > start) {
                size_t len = end_brace - start - 1;
                char *path = strndup(start + 1, len);
                char *trimmed_path = trim_spaces(path);
                config->path_secure = trimmed_path;
                free(path);
            }
            free(line_copy);
            continue;
        }

        char *token = strtok(trimmed_line, " \t");
        if (token) {
            cap_rule_t *rule = calloc(1, sizeof(cap_rule_t));
            if (!rule) {
                perror(RED "Failed to allocate memory for rule" RESET);
                exit(EXIT_FAILURE);
            }

            if (strncmp(token, "user-[", 6) == 0) {
                rule->is_user_rule = 1;
                char *name_end = strchr(token + 6, ']');
                if (name_end) {
                    *name_end = '\0';
                    rule->name = strdup(token + 6);
                } else {
                    free(rule);
                    free(line_copy);
                    continue;
                }
            } else if (strncmp(token, "group-[", 7) == 0) {
                rule->is_user_rule = 0;
                char *name_end = strchr(token + 7, ']');
                if (name_end) {
                    *name_end = '\0';
                    rule->name = strdup(token + 7);
                } else {
                    free(rule);
                    free(line_copy);
                    continue;
                }
            } else {
                free(rule);
                free(line_copy);
                continue;
            }

            while ((token = strtok(NULL, " \t"))) {
                if (strcmp(token, "allow-caps") == 0) {
                    token = strtok(NULL, " \t");
                    if (!token) {
                        free(rule->name);
                        free(rule);
                        free(line_copy);
                        goto next_line;
                    }
                    if (strcmp(token, "all") == 0) {
                        rule->allow_all_caps = 1;
                    } else {
                        char *caps_token = strtok(token, ",");
                        while (caps_token && rule->num_allow_caps < 64) {
                            cap_value_t cap;
                            if (cap_from_name(caps_token, &cap) == 0) {
                                rule->allow_caps[rule->num_allow_caps++] = cap;
                            } else {
                                free(rule->name);
                                free(rule);
                                free(line_copy);
                                goto next_line;
                            }
                            caps_token = strtok(NULL, ",");
                        }
                    }
                } else if (strcmp(token, "deny-caps") == 0) {
                    token = strtok(NULL, " \t");
                    if (!token) {
                        free(rule->name);
                        free(rule);
                        free(line_copy);
                        goto next_line;
                    }
                    if (strcmp(token, "all") == 0) {
                        rule->deny_all_caps = 1;
                    } else {
                        char *caps_token = strtok(token, ",");
                        while (caps_token && rule->num_deny_caps < 64) {
                            cap_value_t cap;
                            if (cap_from_name(caps_token, &cap) == 0) {
                                rule->deny_caps[rule->num_deny_caps++] = cap;
                            } else {
                                free(rule->name);
                                free(rule);
                                free(line_copy);
                                goto next_line;
                            }
                            caps_token = strtok(NULL, ",");
                        }
                    }
                } else if (strcmp(token, "NOPASSWD") == 0) {
                    rule->nopasswd = 1;
                } else {
                    free(rule->name);
                    free(rule);
                    free(line_copy);
                    goto next_line;
                }
            }

            if (rule->is_user_rule) {
                struct passwd *pw = getpwnam(rule->name);
                if (pw) {
                    rule->uid = pw->pw_uid;
                } else {
                    rule->uid = atoi(rule->name);
                }
            } else {
                struct group *gr = getgrnam(rule->name);
                if (gr) {
                    rule->gid = gr->gr_gid;
                } else {
                    rule->gid = atoi(rule->name);
                }
            }

            rule->next = config->rules;
            config->rules = rule;
        } else {
            /* Invalid line */
        }

    next_line:
        free(line_copy);
    }

    fclose(file);
}

void apply_capabilities(config_t *config, uid_t uid, gid_t gid, gid_t *supp_gids, int num_supp_gids) {
    cap_t caps;
    cap_value_t all_caps[] = {
        CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_FSETID,
        CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP, CAP_LINUX_IMMUTABLE,
        CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, CAP_NET_ADMIN, CAP_NET_RAW,
        CAP_IPC_LOCK, CAP_IPC_OWNER, CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_SYS_CHROOT,
        CAP_SYS_PTRACE, CAP_SYS_PACCT, CAP_SYS_ADMIN, CAP_SYS_BOOT, CAP_SYS_NICE,
        CAP_SYS_RESOURCE, CAP_SYS_TIME, CAP_SYS_TTY_CONFIG, CAP_MKNOD, CAP_LEASE,
        CAP_AUDIT_WRITE, CAP_AUDIT_CONTROL, CAP_SETFCAP, CAP_MAC_OVERRIDE,
        CAP_MAC_ADMIN, CAP_SYSLOG, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND,
        CAP_AUDIT_READ, CAP_PERFMON, CAP_BPF, CAP_CHECKPOINT_RESTORE
    };
    size_t num_caps = sizeof(all_caps) / sizeof(cap_value_t);

    caps = cap_init();
    if (caps == NULL) {
        perror(RED "Failed to initialize capabilities" RESET);
        exit(EXIT_FAILURE);
    }

    // Track allowed and denied capabilities
    int allowed_caps[CAP_LAST_CAP + 1] = {0};
    int denied_caps[CAP_LAST_CAP +1] = {0};
    int all_caps_allowed = 1;
    int all_caps_denied = 1;

    // Iterate over config rules to set capabilities
    cap_rule_t *rule = config->rules;
    while (rule) {
        int applies = 0;

        // Check if rule applies to current user or groups
        if (rule->is_user_rule && rule->uid == uid) {
            applies = 1;
        } else if (!rule->is_user_rule && rule->gid == gid) {
            applies = 1;
        } else {
            for (int i = 0; i < num_supp_gids; i++) {
                if (rule->gid == supp_gids[i]) {
                    applies = 1;
                    break;
                }
            }
        }

        if (applies) {
            // Process allow/deny rules
            if (rule->allow_all_caps) {
                all_caps_denied = 0;
                for (int i = 0; i < 64; i++) {
                    allowed_caps[i] = 1;
                }
            } else if (rule->deny_all_caps) {
                all_caps_allowed = 0;
                for (int i = 0; i < 64; i++) {
                    denied_caps[i] = 1;
                }
            } else {
                for (int i = 0; i < rule->num_allow_caps; i++) {
                    allowed_caps[rule->allow_caps[i]] = 1;
                    denied_caps[rule->allow_caps[i]] = 0;
                    all_caps_denied = 0;
                }
                for (int i = 0; i < rule->num_deny_caps; i++) {
                    denied_caps[rule->deny_caps[i]] = 1;
                    allowed_caps[rule->deny_caps[i]] = 0;
                    all_caps_allowed = 0;
                }
            }
        }

        rule = rule->next;
    }

    // Apply capabilities based on allowed/denied configuration
    for (int i = 0; i < num_caps; i++) {
        if (allowed_caps[all_caps[i]] && !denied_caps[all_caps[i]]) {
            if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &all_caps[i], CAP_SET) == -1 ||
                cap_set_flag(caps, CAP_PERMITTED, 1, &all_caps[i], CAP_SET) == -1 ||
                cap_set_flag(caps, CAP_INHERITABLE, 1, &all_caps[i], CAP_SET) == -1) {
                perror(RED "Failed to set capability" RESET);
                cap_free(caps);
                exit(EXIT_FAILURE);
            }
        }
    }

    if (cap_set_proc(caps) == -1) {
        perror(RED "Failed to apply capabilities to process" RESET);
        cap_free(caps);
        exit(EXIT_FAILURE);
    }

    cap_free(caps);
}

void display_user_capabilities(config_t *config, uid_t uid, gid_t gid, gid_t *supp_gids, int num_supp_gids) {
    int all_caps_allowed = 1;
    int all_caps_denied = 1;
    int allowed_setgid = 1;
    int allowed_setuid = 1;
    int found_applicable_rule = 0;  // Track if any rule applies to the user

    // Arrays to track allowed or denied capabilities
    int allowed_caps[CAP_LAST_CAP + 1] = {0};
    int denied_caps[CAP_LAST_CAP + 1] = {0};

    cap_rule_t *rule = config->rules;
    while (rule) {
        int applies = 0;
        if (rule->is_user_rule && rule->uid == uid) {
            applies = 1;
        } else if (!rule->is_user_rule && rule->gid == gid) {
            applies = 1;
        } else {
            for (int i = 0; i < num_supp_gids; i++) {
                if (rule->gid == supp_gids[i]) {
                    applies = 1;
                    break;
                }
            }
        }

        if (applies) {
            found_applicable_rule = 1;  // Mark that we found a rule

            // Process allow/deny rules
            if (rule->allow_all_caps) {
                all_caps_denied = 0;
                for (int i = 0; i < 64; i++) {
                    allowed_caps[i] = 1;
                }
            } else if (rule->deny_all_caps) {
                all_caps_allowed = 0;
                for (int i = 0; i < 64; i++) {
                    denied_caps[i] = 1;
                }
            } else {
                for (int i = 0; i < rule->num_allow_caps; i++) {
                    allowed_caps[rule->allow_caps[i]] = 1;
                    denied_caps[rule->allow_caps[i]] = 0;
                    all_caps_denied = 0;
                }
                for (int i = 0; i < rule->num_deny_caps; i++) {
                    denied_caps[rule->deny_caps[i]] = 1;
                    allowed_caps[rule->deny_caps[i]] = 0;
                    all_caps_allowed = 0;
                }
            }

            if (rule->deny_all_caps || (rule->num_deny_caps > 0 && denied_caps[CAP_SETUID])) {
                allowed_setuid = 0;
            }
            if (rule->deny_all_caps || (rule->num_deny_caps > 0 && denied_caps[CAP_SETGID])) {
                allowed_setgid = 0;
            }
        }
        rule = rule->next;
    }

    if (!found_applicable_rule) {
        // If no applicable rule was found, output "Nothing" allowed
        printf(RED "Nothing\n" RESET);
        printf("You do not have permission to switch users\n");
        return;
    }

    // Existing code to print allowed and denied capabilities if rules apply
    if (all_caps_allowed) {
        printf(GREEN "Everything\n" RESET);
    } else if (all_caps_denied) {
        printf(RED "Nothing\n" RESET);
        printf("You do not have permission to switch users\n");
    } else {
        printf(BLUE "You are allowed the following capabilities:\n" RESET);

        for (int i = 0; i < 64; i++) {
            if (allowed_caps[i]) {
                printf(GREEN "cap_%d\n" RESET, i);
            } else if (denied_caps[i]) {
                printf(RED "cap_%d\n" RESET, i);
            }
        }

        if (!allowed_setgid && !allowed_setuid) {
            printf(RED "You cannot use -u, -g, or -G\n" RESET);
        } else if (!allowed_setgid) {
            printf(RED "You cannot use -g or -G\n" RESET);
        } else if (!allowed_setuid) {
            printf(RED "You cannot use -u\n" RESET);
        }
    }
}

int authenticate_user(const char *username) {
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = {
        misc_conv,
        NULL
    };
    int retval = pam_start("osu", username, &conv, &pamh);
    if (retval == PAM_SUCCESS) {
        retval = pam_authenticate(pamh, 0);
    }
    if (retval == PAM_SUCCESS) {
        retval = pam_acct_mgmt(pamh, 0);
    }
    pam_end(pamh, retval);
    return (retval == PAM_SUCCESS) ? 0 : -1;
}

void set_all_caps() {
    cap_t caps;
    int max_caps = CAP_LAST_CAP + 1;
    cap_value_t *all_caps = malloc(max_caps * sizeof(cap_value_t));
    if (!all_caps) {
        perror(RED "Failed to allocate memory for all_caps" RESET);
        exit(EXIT_FAILURE);
    }
    size_t num_caps = 0;
    for (int i = 0; i <= CAP_LAST_CAP; i++) {
        all_caps[num_caps++] = i;
    }

    caps = cap_get_proc();
    if (caps == NULL) {
        perror(RED "Failed to get capabilities" RESET);
        free(all_caps);
        exit(EXIT_FAILURE);
    }

    if (cap_set_flag(caps, CAP_EFFECTIVE, num_caps, all_caps, CAP_SET) == -1 ||
        cap_set_flag(caps, CAP_PERMITTED, num_caps, all_caps, CAP_SET) == -1 ||
        cap_set_flag(caps, CAP_INHERITABLE, num_caps, all_caps, CAP_SET) == -1 ||
        cap_set_proc(caps) == -1) {
        perror(RED "Failed to set all capabilities" RESET);
        cap_free(caps);
        free(all_caps);
        exit(EXIT_FAILURE);
    }
    cap_free(caps);

    for (size_t i = 0; i < num_caps; ++i) {
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, all_caps[i], 0, 0) == -1) {
            perror(RED "Failed to raise capability in ambient set" RESET);
            free(all_caps);
            exit(EXIT_FAILURE);
        }
    }
    free(all_caps);
}

void free_config(config_t *config) {
    if (config->path_secure) {
        free(config->path_secure);
    }
    cap_rule_t *rule = config->rules;
    while (rule) {
        cap_rule_t *next = rule->next;
        free(rule->name);
        free(rule);
        rule = next;
    }
}
