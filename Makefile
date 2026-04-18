ROOT ?= $(abspath ../../..)
include $(ROOT)/mk/vars.mk
.PHONY: all clean asan ubsan tsan
SCOUT_DIR := $(ROOT)/clients/scoutless/src
SCOUT_SRC := $(wildcard $(SCOUT_DIR)/*.c)
ifeq ($(strip $(SCOUT_SRC)),)
$(error SCOUT_SRC empty: no .c files found in $(SCOUT_DIR))
endif
CFLAGS_CLIENTS := $(CFLAGS_COMMON)
WIN_CFLAGS ?= -O2 -pipe -Wall -Wextra -Werror -D_GNU_SOURCE -std=c11 -DWINVER=0x0600 -D_WIN32_WINNT=0x0600
CFLAGS_CLIENTS_WIN := $(WIN_CFLAGS)
CFLAGS_CLIENTS_NDK := $(CFLAGS_COMMON)
CFLAGS_CLIENTS_ASAN := -g -O1 -pipe -Wall -Wextra -Werror -D_GNU_SOURCE -std=c11 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer
CFLAGS_CLIENTS_UBSAN := -g -O1 -pipe -Wall -Wextra -Werror -D_GNU_SOURCE -std=c11 -fsanitize=undefined -fno-omit-frame-pointer
CFLAGS_CLIENTS_TSAN := -g -O0 -pipe -Wall -Wextra -Werror -D_GNU_SOURCE -std=c11 -fsanitize=thread -fno-omit-frame-pointer -fno-optimize-sibling-calls
LDFLAGS_CLIENTS_ASAN := -fsanitize=address -fsanitize=undefined
LDFLAGS_CLIENTS_UBSAN := -fsanitize=undefined
LDFLAGS_CLIENTS_TSAN := -fsanitize=thread
LDLIBS_SCOUT_WIN := -liphlpapi
LDLIBS_WIN_BASE := -lws2_32
ANDROID_BIN_DIR := $(BIN_DIR)
all: $(BIN_DIR) $(BIN_DIR)/scoutless-linux-amd64 $(ANDROID_BIN_DIR)/scoutless-android-armv7 $(ANDROID_BIN_DIR)/scoutless-android-arm64
asan: $(BIN_DIR) $(BIN_DIR)/scoutless-asan
ubsan: $(BIN_DIR) $(BIN_DIR)/scoutless-ubsan
tsan: $(BIN_DIR) $(BIN_DIR)/scoutless-tsan
$(BIN_DIR)/scoutless-linux-amd64: $(SCOUT_SRC) | $(BIN_DIR)
	$(MUSL_CC_LINUX) $(CFLAGS_CLIENTS) -o $@ $(filter %.c,$^) $(LDFLAGS_STATIC)
	$(MUSL_STRIP_LINUX) $(STRIP_FLAGS) $@
$(BIN_DIR)/scoutless-linux-arm64: $(SCOUT_SRC) | $(BIN_DIR)
	$(MUSL_CC_ARM64) $(CFLAGS_CLIENTS) -o $@ $(filter %.c,$^) $(LDFLAGS_STATIC)
	$(MUSL_STRIP_ARM64) $(STRIP_FLAGS) $@
$(BIN_DIR)/scoutless-linux-armv7: $(SCOUT_SRC) | $(BIN_DIR)
	$(MUSL_CC_ARMV7) $(CFLAGS_CLIENTS) -o $@ $(filter %.c,$^) $(LDFLAGS_STATIC)
	$(MUSL_STRIP_ARMV7) $(STRIP_FLAGS) $@
$(ANDROID_BIN_DIR)/scoutless-android-armv7: $(SCOUT_SRC) | $(ANDROID_BIN_DIR)
	$(CC_ANDROID_ARMV7) $(CFLAGS_CLIENTS_NDK) -o $@ $(filter %.c,$^)
	$(NDK_BIN)/llvm-strip $(STRIP_FLAGS) $@ || true
$(ANDROID_BIN_DIR)/scoutless-android-arm64: $(SCOUT_SRC) | $(ANDROID_BIN_DIR)
	$(CC_ANDROID_ARM64) $(CFLAGS_CLIENTS_NDK) -o $@ $(filter %.c,$^)
	$(NDK_BIN)/llvm-strip $(STRIP_FLAGS) $@ || true
$(BIN_DIR)/scoutless-windows.exe: $(SCOUT_SRC) | $(BIN_DIR)
	$(CC_WIN) $(CFLAGS_CLIENTS_WIN) -o $@ $(filter %.c,$^) $(LDFLAGS_WIN) $(LDLIBS_WIN_BASE) $(LDLIBS_SCOUT_WIN)
	$(STRIP_WIN) $(STRIP_FLAGS) $@
$(BIN_DIR)/scoutless-asan: $(SCOUT_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS_CLIENTS_ASAN) -o $@ $(filter %.c,$^) $(LDFLAGS_CLIENTS_ASAN)
$(BIN_DIR)/scoutless-ubsan: $(SCOUT_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS_CLIENTS_UBSAN) -o $@ $(filter %.c,$^) $(LDFLAGS_CLIENTS_UBSAN)
$(BIN_DIR)/scoutless-tsan: $(SCOUT_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS_CLIENTS_TSAN) -o $@ $(filter %.c,$^) $(LDFLAGS_CLIENTS_TSAN)
clean:
	@-rm -f "$(BIN_DIR)"/scoutless-linux-amd64 2> /dev/null
	@-rm -f "$(BIN_DIR)"/scoutless-linux-arm64 2> /dev/null
	@-rm -f "$(BIN_DIR)"/scoutless-linux-armv7 2> /dev/null
	@-rm -f "$(BIN_DIR)"/scoutless-windows.exe 2> /dev/null
	@-rm -f "$(ANDROID_BIN_DIR)"/scoutless-android-armv7 2> /dev/null
	@-rm -f "$(ANDROID_BIN_DIR)"/scoutless-android-arm64 2> /dev/null
	@-rm -f "$(BIN_DIR)"/scoutless-asan 2> /dev/null
	@-rm -f "$(BIN_DIR)"/scoutless-ubsan 2> /dev/null
	@-rm -f "$(BIN_DIR)"/scoutless-tsan 2> /dev/null