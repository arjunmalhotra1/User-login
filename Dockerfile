FROM golang:1.15-alpine3.14

WORKDIR /usr/src/application-USERLOGIN
ENV GO111MODULE=on
COPY ./ ./
RUN apk add bash libc-dev
RUN go mod download
EXPOSE 8086
#CMD ["/bin/bash"]