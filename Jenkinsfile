pipeline {
    agent any

    environment {
        JAVA_HOME = 'C:\\Program Files\\Eclipse Adoptium\\jdk-17.0.15.6-hotspot'  // Adjust to your JDK path
        PATH = "${env.JAVA_HOME}\\bin;${env.PATH}"
    }

    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/JieHui-Git/encryption-app.git'
            }
        }

        stage('Build Frontend') {
            steps {
                dir('frontend') {
                    bat 'npm install'
                    bat 'npm run build'
                }
            }
        }

        stage('Build Backend') {
            steps {
                dir('backend') {
                    bat 'mvn clean package'
                }
            }
        }

        stage('Archive Artifacts') {
            steps {
                archiveArtifacts artifacts: 'backend/target/*.jar', fingerprint: true
                archiveArtifacts artifacts: 'frontend/build/**', fingerprint: true
            }
        }
    }
}
