# At time of writing (Aug 29, 2022) this was ubuntu:22.04
FROM ubuntu:latest

# install some dependencies
RUN apt update && apt install -y curl
RUN apt install git m4 z3 cmake libboost-all-dev build-essential -y

# install rust
RUN mkdir -p /user/build-rust/src
WORKDIR /user/build-rust/src
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# clone the repo
RUN mkdir -p /user/src
WORKDIR /user/src
RUN git clone https://github.com/nirvantyagi/versa.git
WORKDIR ./versa

# build
RUN cargo build
