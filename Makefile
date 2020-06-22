VERSION="0.1.0"
.DEFAULT_GOAL := build
build:
	sudo docker build . --tag=pfcp-tool:$(VERSION)
