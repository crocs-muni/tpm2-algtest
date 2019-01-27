FROM fedora:29

RUN dnf install --assumeyes clang cmake make tpm2-tss-devel openssl-devel

COPY . /tpm2-algtest

WORKDIR /tpm2-algtest/build

RUN cmake .. && make

CMD ["./tpm2_algtest"]
