CFLAGS += -Wall -Werror -std=c99
#CFLAGS += -O0 -g -DDEBUG
CFLAGS += -Os -DNDEBUG

PROGS = limiter tester

all: $(PROGS) .limiter-setuid
    
limiter: limiter.o Hashtable.o
tester: tester.o

.limiter-setuid: limiter
	sudo chown root:staff $<
	sudo chmod u+s $<
	sudo chmod a+w $<
	touch $@

clean:
	rm -f *.o 
	sudo rm -f $(PROGS)