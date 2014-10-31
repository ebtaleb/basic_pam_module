all: install

install: basic_pam.so test
	sudo cp $^ /lib/security
	sudo cp test.pamconf /etc/pam.d/test

basic_pam.so: basic_pam.c
	gcc -fPIC -DPIC -shared -rdynamic -o $@ $^

test: test.c
	gcc -o $@ $^ -lpam -lpam_misc

.PHONY: clean

clean:
	rm basic_pam.so
	rm test
	sudo rm /lib/security/basic_pam.so
	sudo rm /etc/pam.d/test
