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

//         // Linux x86
//         [os: 'linux',   arch: 'amd64',  arm: '',  ext: ''],
//         [os: 'linux',   arch: '386',    arm: '',  ext: ''],
//
//         // Linux ARM64 (modern ARM servers, Pi 4/5 64-bit)
//         [os: 'linux',   arch: 'arm64',  arm: '',  ext: ''],
//
//         // Raspberry Pi — 32-bit (Pi Zero, Pi 1: ARMv6 / Pi 2+: ARMv7)
//         [os: 'linux',   arch: 'arm',    arm: '6', ext: ''],
//         [os: 'linux',   arch: 'arm',    arm: '7', ext: ''],
//
//         // macOS
//         [os: 'darwin',  arch: 'amd64',  arm: '',  ext: ''],
//         [os: 'darwin',  arch: 'arm64',  arm: '',  ext: ''],  // Apple Silicon
//
//         // FreeBSD
//         [os: 'freebsd', arch: 'amd64',  arm: '',  ext: ''],
//         [os: 'freebsd', arch: 'arm64',  arm: '',  ext: ''],
    ]

    node(env.BUILD_NODE) {

        def appName        = 'proxylogin'
        def goVersion      = '1.26'
        def goImage        = "golang:${goVersion}-alpine"
        def redisImage     = "redis:8-alpine"

        def buildId = ''
        def volumeName = ''
        def networkName = ''
        def goDockerArgs = ''
        def gitCommit = ''
        def gitTag    = ''

        def cleanup

        def generateBinaryName = { String extension ->
            return "${appName}${extension}"
        }

        def generateLabel = { String os, String arch, String arm ->
            def label = "${os}-${arch}"
            if (arm) { label += "-armv${arm}" }
            return label
        }

        def generateFolderName = { String os, String arch, String arm ->
            return arm
                   ? "${os}-${arch}v${arm}"
                   : "${os}-${arch}"
        }

        def generateArchiveName = { String os, String arch, String arm ->
            return arm
                   ? "${appName}-${os}-${arch}v${arm}.zip"
                   : "${appName}-${os}-${arch}.zip"
        }

        def generateChecksumFileName = { String os, String arch, String arm ->
            return arm
                   ? "SHA256-${os}-${arch}v${arm}.txt"
                   : "SHA256-${os}-${arch}.txt"
        }

        // ----------------------------------------------------------
        // Stage: Checkout
        // ----------------------------------------------------------
        stage('Checkout') {
            deleteDir()
            checkout scm

            gitCommit = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
            gitTag    = sh(script: 'git tag --points-at HEAD', returnStdout: true).trim()

            echo "Commit: ${gitCommit}  Tag: ${gitTag ?: '(none)'}"
        }


        try {
            stage('Prepare') {
                buildId = "${gitCommit}_${env.BUILD_NUMBER}"
                volumeName = "proxylogin_${buildId}"
                goDockerArgs  = "-e CGO_ENABLED=0 -e GOCACHE=/tmp/go-cache -v ${volumeName}:/tmp/go-cache -e GOMODCACHE=/tmp/go-mod -v ${volumeName}:/tmp/go-mod"
                networkName = "proxylogin_${buildId}"

                sh "docker network create -d bridge ${networkName}"
                sh "docker volume create ${volumeName}"

                cleanup = {
                    sh "docker volume rm -f ${volumeName}"
                    sh "docker network rm -f ${networkName}"
                }

                docker.image('alpine').run("-v ${volumeName}:/tmp", "chmod -R 777 /tmp").stop()
            }

            // ----------------------------------------------------------
            // Stage: Test
            // ----------------------------------------------------------
            stage('Test') {
                def buildSteps = [:]
                def infraReady = false
                def testsDone = false

                def redisContainer = docker.image(redisImage).run("--network=${networkName} --hostname=redis")

                docker.image(goImage).inside("${goDockerArgs} --network=${networkName} -e REDIS_URL=redis://redis:6379/0?protocol=3") {
                    sh 'go vet ./...'
                    sh 'go test -v -coverprofile=coverage.out ./...'
                    sh 'go tool cover -func=coverage.out'
                }

                redisContainer.stop()
            }

            // ----------------------------------------------------------
            // Stage: Build
            // ----------------------------------------------------------

            stage('Build') {
                def binaryVersion = gitTag ?: gitCommit
                docker.image(goImage).inside(goDockerArgs) {
                    for (target in targets) {
                        withEnv([
                            "GOOS=${target.os}",
                            "GOARCH=${target.arch}",
                            "GOARM=${target.arm}"
                        ]) {
                            def label = generateLabel(target.os, target.arch, target.arm)
                            def folderName = generateFolderName(target.os, target.arch, target.arm)
                            def binaryName = generateBinaryName(target.ext)

                            sh """
                                echo "Building ${label}..."
                                go build \
                                    -trimpath \
                                    -ldflags="-s -w \
                                        -X main.version=${binaryVersion} \
                                        -X main.commit=${gitCommit} \
                                        -X main.buildDate=\$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                                    -o dist/${folderName}/${binaryName} \
                                    ./cmd/${appName}
                            """
                        }
                    }
                }
            }
        } catch(e) {
            cleanup()
            throw e
        }

        stage('Cleanup') {
            cleanup()
        }

        stage('Compress') {
            sh "mkdir -p dist/compressed"
            for (target in targets) {
                def archiveName = generateArchiveName(target.os, target.arch, target.arm)
                def folderName = generateFolderName(target.os, target.arch, target.arm)
                def binaryName = generateBinaryName(target.ext)
                def checksumPath = "dist/${folderName}/${generateChecksumFileName(target.os, target.arch, target.arm)}"

                zip zipFile:"dist/compressed/${archiveName}", dir: "dist/${folderName}/"

                sh """
                    sha256sum dist/${folderName}/${binaryName} > ${checksumPath}
                    echo >> ${checksumPath}
                    sha256sum dist/compressed/${archiveName} >> ${checksumPath}
                """
            }
        }

        // ----------------------------------------------------------
        // Stage: Archive
        // ----------------------------------------------------------
        stage('Archive') {
            archiveArtifacts artifacts: 'dist/**/SHA256-*.txt,dist/compressed/*.zip', fingerprint: true
            echo "Artifacts archived: dist/"
        }

        // ----------------------------------------------------------
        // Stage: Publish (runs only on tagged commits)
        // ----------------------------------------------------------
        stage('Publish') {
            if (gitTag) {
                echo "Tagged release ${gitTag} — publishing artifacts..."
                withCredentials([string(credentialsId: 'proxy-login-jenkins', variable: 'GH_TOKEN')]) {
                    sh """
                        gh release create ${gitTag} 'dist/**/*.zip' 'dist/**/*.txt' \
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
