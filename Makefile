DESTDIR?=
PREFIX?=/usr
INSTALL_DIR?= install -d
INSTALL_BIN?= install -m 755
INSTALL_DATA?= install -m 666
DEBUG?=0

CFLAGS += -Wall -Werror -Wmissing-prototypes -std=gnu11
CFLAGS += -D_GNU_SOURCE -DDEBUG=$(DEBUG)
CFLAGS += -I$(CURDIR)

LIBS=-lubus -lubox

OBJS = \
	file_monitor.o\
	log.o\
	log_ubus.o\
	serviced.o\
	serviced_ubus.o\
	service.o\
	string_constants.o\
	ubus_connection.o\
	utils.o

TARGET=serviced

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) $(LDLIBS) -o $@

.PHONY: install
install: $(TARGET)
	$(INSTALL_DIR) $(DESTDIR)$(PREFIX)/bin
	$(INSTALL_BIN) $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

.PHONY: clean
clean:
	@-rm -f $(TARGET)
	@-find . -type f -name '*.[od]' -delete

CFLAGS += -MMD -MP
-include $(OBJS:%.o=%.d)

