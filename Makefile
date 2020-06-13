VERSION="0.1.0"
.DEFAULT_GOAL := build
build:
	docker build . --tag=pfcp-tool:$(VERSION)
