// Decionis govern: one verdict before this stage's command runs, with a
// signed Decision Dossier of it. Written by `govern init`; paste the stage
// into your Jenkinsfile's `stages` and add the credential it names.
//
// Shadow first: the stage never fails a build, and until the credential
// exists it records nothing. Add a secret-text credential `decionis-api-key`
// and the tenant id from https://decionis.com/quickstart, watch the verdicts,
// then set GOVERN_MODE to enforce and gate the command that matters.
stage('Govern') {
  environment {
    DECIONIS_API_KEY = credentials('decionis-api-key')
    DECIONIS_TENANT_ID = '00000000-0000-0000-0000-000000000000' // the workspace's UUID
    GOVERN_MODE = '{{MODE}}'
    GOVERN_ACTION = '{{ACTION}}'
    GOVERN_OUTPUT_FILE = 'govern.env'
  }
  steps {
    sh 'curl -fsSL https://raw.githubusercontent.com/decionis/agent-safe-pipeline/master/govern/install.sh | GOVERN_VERSION={{VERSION}} GOVERN_INSTALL_PREFIX="$WORKSPACE/.govern" sh'
    sh 'PATH="$WORKSPACE/.govern/bin:$PATH" govern run -- true' // replace `true` with the command the verdict gates
  }
}
