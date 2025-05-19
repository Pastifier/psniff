NAME		:= psniff

CC			:= gcc
CFLAGS		:= -Wall -Wextra -Werror -g3
LDFLAGS		:= -lpthread -lpcap

INCLUDE		:= psniff.h ps_queue.h ps_threads.h
INCLUDES	:= $(addprefix include/, $(INCLUDE))

SRC		:= main.c ps_queue.c ps_threads.c ps_track.c ps_capture.c ps_consumer.c
SRCS		:= $(addprefix src/, $(SRC))

all: $(NAME)

$(NAME): $(SRCS) $(INCLUDES)
	$(CC) -o $@ -Iinclude/ $(CFLAGS) $^ $(LDFLAGS)

fclean:
	rm -rf $(NAME)

re: fclean all

.PHONY: fclean all
