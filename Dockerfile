FROM alpine:latest  

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

COPY chat-server .

EXPOSE 8080

CMD ["./chat-server"]
