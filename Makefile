MAKEFLAGS += --always-make

NAME := cardaci.xyz

run: build
	docker run \
		--rm \
		--interactive \
		--tty \
		--publish 4000:4000 \
		$(NAME)


build:
	docker build \
		--tag $(NAME) \
		.

clean:
	docker rmi $(NAME)
