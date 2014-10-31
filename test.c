#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <stdlib.h>

static struct pam_conv conv = { misc_conv, NULL };

int main(int argc, char *argv[])
{
    pam_handle_t *pamh = NULL;
    const char *user = "masked_rider";
    int return_value;

    if (argc == 2) {
        user = argv[1];
    }

    if (argc > 2) {
        fprintf(stderr, "Usage: check_user [username]\n");
        exit(1);
    }

    if ((return_value = pam_start("test", user, &conv, &pamh)) != PAM_SUCCESS)
        goto error_handler;

    // have we been authentificated?
    if ((return_value = pam_authenticate(pamh, 0)) != PAM_SUCCESS)
        goto error_handler;
    else
        fprintf(stdout, "Great success!\n Welcome %s\n", user);

    if ((return_value = pam_open_session(pamh, 0)) != PAM_SUCCESS)
        goto error_handler;

    printf("Session opened, doing our stuff...\n");

    // do our stuff
    system("/bin/ls -la");

    printf("we are done here, closing session\n");

error_handler:
    if ((return_value = pam_close_session(pamh, 0)) != PAM_SUCCESS) {
        perror("nope");
        exit(1);
    }

    pam_end(pamh, return_value);

    if (return_value == PAM_SUCCESS) {
        exit(0);
    } else {
        fprintf(stdout, "Not Authenticated\n");
        exit(1);
    }

}
