# ---------- Build stage ----------
FROM eclipse-temurin:17-jdk AS build
WORKDIR /app

# Copy only files needed to resolve deps first (faster cached builds)
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN chmod +x mvnw
RUN ./mvnw -B -DskipTests dependency:go-offline

# Now copy source and build
COPY src/ src/
RUN ./mvnw -B -DskipTests package

# ---------- Runtime stage ----------
FROM eclipse-temurin:17-jre
WORKDIR /app

# Copy the built jar
COPY --from=build /app/target/*.jar app.jar

# Render sets PORT; expose is informational
EXPOSE 8080
ENV PORT=8080

# Use PORT for Spring Boot server port
CMD ["sh", "-c", "java -Dserver.port=${PORT} -jar app.jar"]
