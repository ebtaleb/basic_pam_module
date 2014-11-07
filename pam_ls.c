#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <stdlib.h>

static struct pam_conv conv = { misc_conv, NULL };

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: pam_ls [unix_username]\n");
        exit(1);
    }

    pam_handle_t *pamh = NULL;
    int return_value;
    const char *user = argv[1];

    if ((return_value = pam_start("pam_ls", user, &conv, &pamh)) != PAM_SUCCESS)
        goto error_handler;

    // have we been authentificated?
    if ((return_value = pam_authenticate(pamh, 0)) != PAM_SUCCESS)
        goto error_handler;

    if ((return_value = pam_open_session(pamh, 0)) != PAM_SUCCESS)
        goto error_handler;

    // do our stuff
    system("/bin/ls -la");

    if ((return_value = pam_close_session(pamh, 0)) != PAM_SUCCESS)
        goto error_handler;

error_handler:

    pam_end(pamh, return_value);

    if (return_value == PAM_SUCCESS) {
        exit(0);
    } else {
        fprintf(stdout, "Not Authenticated\n");
        exit(1);
    }

}
