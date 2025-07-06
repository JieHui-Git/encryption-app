FROM openjdk:8-jdk-alpine
WORKDIR /app
COPY . .
RUN ./mvnw clean install
CMD ["java", "-jar", "target/demo-0.0.1-SNAPSHOT.jar"]
