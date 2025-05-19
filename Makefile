NAME		:= psniff

CC			:= gcc
CFLAGS		:= -Wall -Wextra -Werror -g3
LDFLAGS		:= -lpthread -lpcap -lm #-fsanitize=address,undefined

# Add Valgrind annotations support
VALGRIND		?= 0
ifeq ($(VALGRIND), 1)
	CFLAGS += -DUSE_VALGRIND_ANNOTATIONS
endif

# Include directories
INC_DIR		:= include
OBJ_DIR		:= obj

# Header files
INCLUDE		:= psniff.h ps_queue.h ps_threads.h ps_valgrind.h
INCLUDES	:= $(addprefix $(INC_DIR)/, $(INCLUDE))

# Source files
SRC		:= main.c ps_queue.c ps_threads.c ps_track.c ps_capture.c ps_consumer.c
SRCS		:= $(addprefix src/, $(SRC))

# Object files
OBJ		:= $(SRC:.c=.o)
OBJS		:= $(addprefix $(OBJ_DIR)/, $(OBJ))

# Default target
all: $(NAME)

# Create obj directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Pattern rule for object files
$(OBJ_DIR)/%.o: src/%.c $(INCLUDES) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# Link the executable
$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Clean object files
clean:
	rm -rf $(OBJ_DIR)

# Clean all generated files
fclean: clean
	rm -f $(NAME)

# Rebuild everything
re: fclean all

# Run with Valgrind annotations enabled
valgrind: fclean
	$(MAKE) VALGRIND=1 all

# Show help
help:
	@echo "Available targets:"
	@echo "  all      : Build the program (default)"
	@echo "  clean    : Remove object files"
	@echo "  fclean   : Remove object files and executable"
	@echo "  re       : Rebuild everything"
	@echo "  valgrind : Build with Valgrind annotations enabled"
sanitize: CFLAGS += -fsanitize=address,undefined -O0 -fno-optimize-sibling-calls -fno-omit-frame-pointer
sanitize: re

fuzz: CC = hfuzz-cc -O3 -flto -fno-stack-protector -fomit-frame-pointer -finline-functions -fno-common -funroll-loops #-funroll-loops #-finline-limit=40000
fuzz: CFLAGS += -fsanitize=address -fsanitize-coverage=trace-pc-guard
fuzz: re
fuzz: 
	mv psniff fuzzdir/psniff

fuzzstart: fuzz
	cd fuzzdir; honggfuzz -i ../pcap_samples/ -o findings/ --crashdir crashes/ -- ./psniff ___FILE___ file fuzz.log

# Declare phony targets
.PHONY: all clean fclean re valgrind help sanitize $(OBJ_DIR)
