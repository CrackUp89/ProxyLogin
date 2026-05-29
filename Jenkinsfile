#!/usr/bin/env groovy

withCredentials([
    string(credentialsId: 'build-node', variable: 'BUILD_NODE')
]) {

    // ============================================================
    // Cross-platform Go build pipeline (scripted style)
    // ============================================================
    // Targets:
    //   Windows  : amd64
    //   Linux    : amd64, arm64, 386
    //   macOS    : amd64, arm64 (Apple Silicon)
    //   Raspberry Pi: linux/arm (v6, v7), linux/arm64
    //   FreeBSD  : amd64, arm64
    // ============================================================

    def targets = [
        // Windows
        [os: 'windows', arch: 'amd64',  arm: '',  ext: '.exe'],
        [os: 'windows', arch: '386',    arm: '',  ext: '.exe'],

        // Linux x86
        [os: 'linux',   arch: 'amd64',  arm: '',  ext: ''],
        [os: 'linux',   arch: '386',    arm: '',  ext: ''],

        // Linux ARM64 (modern ARM servers, Pi 4/5 64-bit)
        [os: 'linux',   arch: 'arm64',  arm: '',  ext: ''],

        // Raspberry Pi — 32-bit (Pi Zero, Pi 1: ARMv6 / Pi 2+: ARMv7)
        [os: 'linux',   arch: 'arm',    arm: '6', ext: ''],
        [os: 'linux',   arch: 'arm',    arm: '7', ext: ''],

        // macOS
        [os: 'darwin',  arch: 'amd64',  arm: '',  ext: ''],
        [os: 'darwin',  arch: 'arm64',  arm: '',  ext: ''],  // Apple Silicon

        // FreeBSD
        [os: 'freebsd', arch: 'amd64',  arm: '',  ext: ''],
        [os: 'freebsd', arch: 'arm64',  arm: '',  ext: ''],
    ]

    def buildSteps = [:]

    node(env.BUILD_NODE) {

        def appName   = 'proxylogin'
        def goVersion = '1.26'
        def goImage   = "golang:${goVersion}-alpine"
        def gitCommit = ''
        def gitTag    = ''

        // ----------------------------------------------------------
        // Stage: Checkout
        // ----------------------------------------------------------
        stage('Checkout') {
            checkout scm
            gitCommit = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
            gitTag    = sh(script: 'git tag --points-at HEAD', returnStdout: true).trim()
            echo "Commit: ${gitCommit}  Tag: ${gitTag ?: '(none)'}"
        }

        // ----------------------------------------------------------
        // Stage: Test
        // ----------------------------------------------------------
        stage('Test') {
            docker.image(goImage).inside('-e CGO_ENABLED=0') {
                sh 'go vet ./...'
                sh 'go test -v -race -coverprofile=coverage.out ./...'
                sh 'go tool cover -func=coverage.out'
            }
            junit allowEmptyResults: true, testResults: '**/test-report.xml'
        }

        // ----------------------------------------------------------
        // Stage: Build (parallel cross-compilation)
        // ----------------------------------------------------------
        stage('Build') {
            for (t in targets) {
                def target = t   // capture loop variable for closure

                def label = "${target.os}-${target.arch}"
                if (target.arm) { label += "-armv${target.arm}" }

                def binaryName = target.arm
                    ? "${appName}-${target.os}-${target.arch}v${target.arm}${target.ext}"
                    : "${appName}-${target.os}-${target.arch}${target.ext}"

                buildSteps[label] = {
                    docker.image(goImage).inside('-e CGO_ENABLED=0') {
                        withEnv([
                            "GOOS=${target.os}",
                            "GOARCH=${target.arch}",
                            "GOARM=${target.arm}",
                            "CGO_ENABLED=0"
                        ]) {
                            sh """
                                echo "Building ${label}..."
                                go build \
                                    -trimpath \
                                    -ldflags="-s -w \
                                        -X main.version=${gitTag ?: gitCommit} \
                                        -X main.commit=${gitCommit} \
                                        -X main.buildDate=\$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                                    -o dist/${binaryName} \
                                    ./cmd/${appName}
                            """
                        }
                    }
                }
            }

            parallel buildSteps
        }

        // ----------------------------------------------------------
        // Stage: Checksum
        // ----------------------------------------------------------
        stage('Checksum') {
            sh 'cd dist && sha256sum * > SHA256SUMS.txt'
            sh 'cat dist/SHA256SUMS.txt'
        }

        // ----------------------------------------------------------
        // Stage: Archive
        // ----------------------------------------------------------
        stage('Archive') {
            archiveArtifacts artifacts: 'dist/**', fingerprint: true
            echo "Artifacts archived: dist/"
        }

        // ----------------------------------------------------------
        // Stage: Publish (runs only on tagged commits)
        // ----------------------------------------------------------
        stage('Publish') {
            if (gitTag) {
                echo "Tagged release ${gitTag} — publishing artifacts..."
                withCredentials([string(credentialsId: 'github-release-token', variable: 'GH_TOKEN')]) {
                    sh """
                        gh release create ${gitTag} dist/* \
                            --title "${gitTag}" \
                            --notes "Release ${gitTag} (${gitCommit})" \
                            --repo \$(git remote get-url origin)
                    """
                }
            } else {
                echo "Not a tagged commit — skipping publish."
            }
        }
    }
}
