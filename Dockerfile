FROM alpine:3.20 AS build
RUN apk add --no-cache nasm binutils make
WORKDIR /src
COPY Makefile ./
COPY src ./src
RUN make all

FROM scratch
COPY --from=build /src/build/val0x04-asm /val0x04-asm
EXPOSE 8080
ENTRYPOINT ["/val0x04-asm"]
