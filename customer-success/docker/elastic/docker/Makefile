NAME = tdong/elasticsearch
VERSION = 1.0.3

.PHONY: all build clean push realclean

all: build

build:
	docker build --rm -t $(NAME):$(VERSION) .

push:
	docker push $(NAME):$(VERSION)

clean:
	docker rmi $(NAME):$(VERSION)

realclean:
	-docker kill $(NAME):$(VERSION) 
	-docker rm $(NAME):$(VERSION)
	-docker rmi $(NAME):$(VERSION)
	-docker system prune -f -a

