#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <sys/time.h>

#define SALT_LENGTH 16
#define MAX_PIN_LENGTH 6
#define PIN_EXPIRATION_TIME 60  // in seconds

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

    for (i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        if (h1[i] != h2[i])
            return 0;
    }

    return 1;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

    char *pin_read = NULL;
    const char *password;
    char *phone_number = NULL;
    char rand_pin[MAX_PIN_LENGTH]= {0};
    char salt[SALT_LENGTH] = {0};
    char rand_pin_and_salt[SALT_LENGTH+MAX_PIN_LENGTH+1] = {0};
    char input[SALT_LENGTH+MAX_PIN_LENGTH+1] = {0};

    SHA512_CTX c;

    unsigned char random_salted_hash[SHA512_DIGEST_LENGTH];
    unsigned char input_salted_hash[SHA512_DIGEST_LENGTH];

    struct timeval start, end;
    double time_elapsed;

	SHA512_Init(&c);
    seedrand();

    int result;

    // pick a OTP PIN between 1000 and 999999
    int num = (999999 - 1000 +1)*(double)rand()/RAND_MAX + 1000;

    // generate a random salt
    int i;
    for (i = 0; i < SALT_LENGTH; ++i){
        salt[i] = '0' + rand() % 72; // starting on '0', ending on '}'
    }

    sprintf(rand_pin, "%d", num);
    sprintf(rand_pin_and_salt, "%d%s", num, salt);
    SHA512_Update(&c,rand_pin_and_salt,(unsigned long)strlen(rand_pin_and_salt));
    SHA512_Final(&(random_salted_hash[0]),&c);

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
    if (time_elapsed > PIN_EXPIRATION_TIME) {
        return PAM_AUTHTOK_ERR;
    }

    sprintf(input, "%s%s", pin_read, salt);
	SHA512_Init(&c);
    SHA512_Update(&c,input,(unsigned long) (strlen(input)));
    SHA512_Final(&(input_salted_hash[0]),&c);

    if (pin_read == NULL || strlen(pin_read) < 4 || strlen(pin_read) > 6) {
        result = PAM_AUTHTOK_ERR;
    } else {
        if (cmp_hash(random_salted_hash, input_salted_hash))
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

