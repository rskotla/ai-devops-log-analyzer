
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    stages {

        stage('Checkout') {
            steps {
                echo 'Source code checked out from GitHub.'
            }
        }

        stage('Check Python') {
            steps {
                sh 'python3 --version'
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                    python3 -m venv .venv
                    .venv/bin/python -m pip install --upgrade pip
                    .venv/bin/python -m pip install -r requirements.txt
                '''
            }
        }

        stage('Run Unit Tests') {
            steps {
                sh '''
                    .venv/bin/python -m unittest discover -s tests -v
                '''
            }
        }

        stage('Generate Sample JSON Reports') {
            steps {
                sh '''
                    .venv/bin/python ci_generate_sample_reports.py
                '''
            }
        }

        stage('Generate HTML Reports') {
            steps {
                sh '''
                    .venv/bin/python html_report_generator.py
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*.json,reports/html/*.html',
                             allowEmptyArchive: true
        }

        success {
            echo 'AI DevOps Log Analyzer CI pipeline completed successfully.'
        }

        failure {
            echo 'Pipeline failed. Check Console Output.'
        }
    }
}
