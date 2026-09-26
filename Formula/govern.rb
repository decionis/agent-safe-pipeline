# The govern formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the static binary the release built for
# this platform; nothing is compiled and no toolchain is needed. The same
# archive is what govern/install.sh downloads and verifies.
class Govern < Formula
  desc "Workflow gate: one Decionis verdict before a CI step runs, with a signed record"
  homepage "https://github.com/decionis/agent-safe-pipeline/tree/master/govern"
  version "2.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.5/govern-2.1.0-darwin-arm64.tar.gz"
      sha256 "39cafcf0293b2575367a6fddae5546e78b3284634ec1038c7aa3dbcc840704cf"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.5/govern-2.1.0-darwin-x64.tar.gz"
      sha256 "c1be16305a43e4f1bf2cbd32b2645bb02b54615ba6be7a14887d5bccb5b5ab02"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.5/govern-2.1.0-linux-arm64.tar.gz"
      sha256 "ac8aaed6353b28215b6ed501a3cec12e7c8df1a277be28b84d733137d00988ad"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.5/govern-2.1.0-linux-x64.tar.gz"
      sha256 "074f4dc76da7625d153d567588d381e9c5f8731563484f93e63c082c063c340b"
    end
  end

  def install
    libexec.install Dir["*"]
    bin.install_symlink libexec/"govern"
  end

  test do
    assert_equal "govern #{version}", shell_output("#{bin}/govern version").strip
    # A shadow step without a key is inert: the command runs, nothing is
    # recorded, and the step ends with the command's own exit code.
    assert_match "shadow", shell_output("#{bin}/govern run --mode shadow --host generic -- true")
  end
end
