TAG = bjhaid/pam_hook:0.4.0

build:
	docker build -t pam_hook -f Dockerfile_build .
	docker run -v $(PWD):/usr/local/go/src/github.com/bjhaid/pam_hook \
	--rm pam_hook \
	/bin/bash -c "cd /usr/local/go/src/github.com/bjhaid/pam_hook && go build"
	docker build --tag $(TAG) .

shell:
	docker run -it -v $(PWD):/usr/local/go/src/github.com/bjhaid/pam_hook \
	--rm pam_hook bash

test: build
	docker run -v $(PWD):/usr/local/go/src/github.com/bjhaid/pam_hook \
	--rm pam_hook \
	/bin/bash -c "cd /usr/local/go/src/github.com/bjhaid/pam_hook && staticcheck github.com/bjhaid/pam_hook && go test"

push: test
	docker push $(TAG)

all: push
