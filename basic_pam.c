#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdlib.h>

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

    char *pin = NULL;
    const char *password;
    const char *username;

    int result, res;
    if ((result = pam_get_user(pamh, &username, "Username: ")) != PAM_SUCCESS)
        return result;

    result = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "Password: ");
    if (result != PAM_SUCCESS)
        return result;

    /*result = pam_get_authtok (pamh, PAM_AUTHTOK, &pin, "A PIN has been sent to your mobile phone.\n Please enter your PIN: ");*/
    /*if (result != PAM_SUCCESS)*/
        /*return result;*/

    result = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &pin, "PIN? ");
    if (result != PAM_SUCCESS)
        return result;

    if (pin == NULL || strlen(pin) != 4) {
        result = PAM_AUTHTOK_ERR;
    } else {
        if(!strcmp(pin, "1234"))
            result = PAM_SUCCESS;
        else
            result = PAM_AUTHTOK_ERR;
    }

    return result;
    /*result = pam_get_authtok(pamh, PAM_AUTHTOK, &pin, "PIN");*/
    /*if (result != PAM_SUCCESS)*/
        /*goto out;*/


}

/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

