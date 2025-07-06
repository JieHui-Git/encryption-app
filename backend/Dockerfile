# Use official OpenJDK base image
FROM eclipse-temurin:17-jdk-jammy

# Create app directory
WORKDIR /app

# Copy your built JAR (adjust filename if needed)
COPY target/encryption-app-0.0.1-SNAPSHOT.jar app.jar

# Expose the port the app runs on
EXPOSE 8080

# Start the application
CMD ["java", "-jar", "app.jar"]
