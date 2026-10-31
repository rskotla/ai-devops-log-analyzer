pipeline {
    agent any

    environment {
        RES_OPTIONS = 'use-vc'
        AZURE_AI_PROJECT_ENDPOINT = 'https://aiops-management.services.ai.azure.com/api/projects/aiops-management-hub'
        AZURE_AI_DEPLOYMENT_NAME = 'gpt-5.4-mini'
    }

    parameters {
        booleanParam(
            name: 'RUN_AI_ANALYSIS',
            defaultValue: false,
            description: 'Enable actual AI log analysis using Azure AI Foundry'
        )
    }

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
                    .venv/bin/python -m pytest -v
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

        stage('AI Log Analysis') {
            when {
                expression {
                    return params.RUN_AI_ANALYSIS
                }
            }

            options {
                timeout(time: 20, unit: 'MINUTES')
            }

            steps {
                echo 'Starting actual AI log analysis using Azure AI Foundry.'

                sh '''
                    .venv/bin/python ai_analyzer.py --source all
                '''
            }
        }

        stage('Generate HTML Reports') {
            steps {
                echo 'Generating individual HTML reports.'

                sh '''
                    .venv/bin/python html_report_generator.py
                    cp report.css reports/html/report.css
                '''
            }
        }

        stage('Generate Central Dashboard') {
            steps {
                echo 'Generating AI DevOps Central Dashboard.'

                sh '''
                    .venv/bin/python dashboard_generator.py
                    cp dashboard.css reports/html/dashboard.css
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*.json,reports/html/*.html,reports/html/*.css',
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
