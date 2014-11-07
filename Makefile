all: install

install: pam_2step_auth.so pam_ls
	sudo cp $^ /lib/security
	sudo cp pam_ls.pamconf /etc/pam.d/pam_ls

pam_2step_auth.so: pam_2step_auth.c
	gcc -g -fPIC -DPIC -shared -rdynamic -o $@ $^

pam_ls: pam_ls.c
	gcc -g -o $@ $^ -lpam -lpam_misc -lcrypto

.PHONY: clean

clean:
	rm pam_2step_auth.so
	rm pam_ls
	sudo rm /lib/security/pam_2step_auth.so
	sudo rm /etc/pam.d/pam_ls
