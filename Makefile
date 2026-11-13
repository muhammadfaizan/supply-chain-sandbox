# Same commands as the npm scripts, for people who prefer make.
#   make doctor
#   make scan
#   make scan TARGET=../my-lib
TARGET ?=

.PHONY: doctor build test scan clean

doctor:
	python3 scripts/sandbox.py doctor

build:
	python3 scripts/sandbox.py build

test:
	python3 scripts/sandbox.py test

scan:
	python3 scripts/sandbox.py scan $(TARGET)

clean:
	rm -rf reports/ .pytest_cache/
