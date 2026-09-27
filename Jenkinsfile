pipeline {
    agent any

    stages {

        stage('Checkout') {
            steps {
                // pulls this project from GitHub
                checkout scm
            }
        }

        stage('Start target app + local AI engine') {
            steps {
                sh 'docker compose up -d'
                // give Juice Shop a few seconds to boot
                sh 'sleep 15'
            }
        }

        stage('Run ZAP security scan') {
            steps {
                sh '''
                    docker run --rm \
                      -v $(pwd):/zap/wrk/:rw \
                      zaproxy/zap-stable zap-baseline.py \
                      -t http://host.docker.internal:3000 \
                      -J zap_report.json || true
                '''
                // zap-baseline.py exits non-zero on findings by design, hence "|| true"
                // (the AI triage stage below is what decides pass/fail instead)
                // Note: host.docker.internal (not --network host) is required on
                // Docker Desktop for Mac, since containers run inside a VM.
            }
        }

        stage('Pull free local AI model (first run only)') {
            steps {
                sh 'docker exec ollama ollama pull llama3.2:1b || true'
            }
        }

        stage('AI-assisted triage') {
            steps {
                sh '''
                    python3 -m venv venv
                    source venv/bin/activate
                    pip install -r requirements.txt
                    python3 triage_ai_local.py zap_report.json
                '''
            }
        }

        stage('Publish report') {
            steps {
                archiveArtifacts artifacts: 'ai_triage_report.md', fingerprint: true
            }
        }
    }

    post {
        always {
            sh 'docker compose down'
        }
    }
}