# The hosts available for testing
HOSTS = naples.cpu picasso.cpu rome.cpu milan.cpu rembrandt.cpu genoa.cpu

.PHONY: test clean

# Check which hosts are online
HOSTS := $(foreach host,$(HOSTS),$(shell ssh $(host) echo $(host)))

test: ../zentool ../mcas ../mcop
	@./print.sh
	@./encrypt.sh
	@./resign.sh
	@./edit.sh
	@./mcas.sh
	@./mcop.sh
	@./setup.sh $(HOSTS)
	@./stop.sh $(HOSTS)
	@./regop.sh $(HOSTS)
	@./specop.sh $(HOSTS)

../zentool ../mcas ../mcop:
	make -C ..

clean:
	rm -f error.*.diff *.rej *.orig
