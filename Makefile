TAG = bjhaid/pam_hook:0.2.0

build:
	docker build -t pam_hook -f Dockerfile_build .
	docker run -v $(PWD):/usr/local/go/src/github.com/bjhaid/pam_hook \
	--rm pam_hook \
	/bin/bash -c "cd /usr/local/go/src/github.com/bjhaid/pam_hook && go build"
	docker build --tag $(TAG) .

push: build
	docker push $(TAG)

all: push
