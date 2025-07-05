# 빌드 환경
FROM amazoncorretto:17 AS builder

WORKDIR /app

COPY . .

RUN chmod +x ./gradlew \
    && ./gradlew clean build


# 실행 환경
FROM amazoncorretto:17

ENV PROJECT_NAME=discodeit \
    PROJECT_VERSION=1.2-M8 \
    JVM_OPTS=""

RUN yum update -y \
    && yum install -y curl \
    && yum clean all

WORKDIR /app

COPY --from=builder /app/build/libs/${PROJECT_NAME}-${PROJECT_VERSION}.jar app.jar

COPY --from=builder /app/src/main/resources/static /app/static

EXPOSE 80

ENTRYPOINT ["sh", "-c", "java $JVM_OPTS -jar ./app.jar"]