FROM fuzzers/atheris:2.0.7-python3.9

ADD . /src
WORKDIR /src
RUN python3 -m pip install .
RUN python3 -m pip install laspy


CMD ["/src/mayhem/fuzz_parser.py"]
