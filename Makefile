DIR := $(shell pwd -L)

# SDCLI
SDCLI_VERSION=v1.5.2
SDCLI=docker run --rm -v "$(DIR):$(DIR)" -w "$(DIR)" asecurityteam/sdcli:$(SDCLI_VERSION)

dep:
	$(SDCLI) go dep

lint:
	$(SDCLI) go lint

clean:
	docker kill nuclei-wrapped-fake-server || true
	docker rm nuclei-wrapped-fake-server || true

run-server: clean
	docker run --name nuclei-wrapped-fake-server -p 80:80 docker.atl-paas.net/asecurityteam/integration-fake-servers:3.1.4 &

test: run-server
	mkdir -p .coverage
	go test -v -cover -race -coverpkg="main" -coverprofile=.coverage/unit.cover.out ./...

coverage:
	# Create coverage report
	# This fixes a permissions issue with the .coverage artifacts
	# in Pipelines where the directory and files are unwriteable.
	mkdir -p .coverage && chmod -R 777 .coverage
	$(SDCLI) go coverage
