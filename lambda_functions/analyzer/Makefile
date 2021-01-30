all:
	docker build -t binaryalert-lambda .
	docker run --rm -it -v ${PWD}:/var/out binaryalert-lambda
