NAME		:= psniff

CC		:= gcc
DEGBUG		:= -g3
CFLAGS		:= -Wall -Wextra -Werror
LDFLAGS		:= -lpthread -lpcap

INCLUDE		:= psniff.h
INCLUDES	:= $(addprefix include/, $(INCLUDE))

SRC		:= main.c
SRCS		:= $(addprefix src/, $(SRC))

all: $(NAME)

$(NAME): $(SRCS) $(INCLUDES)
	$(CC) -o $@ -Iinclude/ $(CFLAGS) $(DEBUG) $^ $(LDFLAGS)

fclean:
	rm -rf $(NAME)

re: fclean all

.PHONY: fclean all
