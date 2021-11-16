build:
	docker build -t marselester/go-libbpf-tools:latest .

run:
	docker run --rm -it --privileged marselester/go-libbpf-tools:latest bash
