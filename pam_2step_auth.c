#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <sys/time.h>

void seedrand() {
    FILE *f = fopen("/dev/urandom", "r");
    unsigned seed;
    fread(&seed, sizeof(seed), 1, f);
    srand(seed);
    fclose(f);
}

int cmp_hash(unsigned char *h1, unsigned char *h2)
{
    int i = 0;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (h1[i] != h2[i])
            return 0;
    }

    return 1;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

    char *pin_read = NULL;
    const char *password;
    char *phone_number = NULL;
    char rand_pin[5]= {0};

	SHA256_CTX c;
	unsigned char md1[SHA256_DIGEST_LENGTH];
	unsigned char md2[SHA256_DIGEST_LENGTH];

    struct timeval start, end;
    double time_elapsed;

	SHA256_Init(&c);
    seedrand();

    int result;

    // pick a OTP PIN between 1000 and 999999
    int num = (999999 - 1000 +1)*(double)rand()/RAND_MAX + 1000;
    sprintf(rand_pin, "%d", num);
    SHA256_Update(&c,rand_pin,(unsigned long)4);
    SHA256_Final(&(md1[0]),&c);

    result = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &phone_number, "Phone number? (65xxxxxxxx): ");
    if (result != PAM_SUCCESS)
        return result;

    if (phone_number == NULL)
        return PAM_AUTHTOK_ERR;

    // send PIN via SMS
    char cmd[50] = {0};
    sprintf(cmd, "./sendsms %s %s", phone_number, rand_pin);
    system(cmd);

    gettimeofday(&start, NULL);

    result = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &pin_read, "PIN? :");
    if (result != PAM_SUCCESS)
        return result;

    gettimeofday(&end, NULL);
    time_elapsed = (double) (end.tv_sec - start.tv_sec)
                   + (double) (end.tv_usec - start.tv_usec) / 1000000;
    if (time_elapsed > 60) {
        return PAM_AUTHTOK_ERR;
    }

	SHA256_Init(&c);
    SHA256_Update(&c,pin_read,(unsigned long)4);
    SHA256_Final(&(md2[0]),&c);

    if (pin_read == NULL || strlen(pin_read) < 4 || strlen(pin_read) > 6) {
        result = PAM_AUTHTOK_ERR;
    } else {
        if (cmp_hash(md1, md2))
            result = PAM_SUCCESS;
        else
            result = PAM_AUTHTOK_ERR;
    }

    return result;

}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {

    fprintf(stdout, "Great success!\n");
    printf("Session opened, doing our stuff...\n");
    return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("we are done here, closing session\n");
    return PAM_SUCCESS;
}

