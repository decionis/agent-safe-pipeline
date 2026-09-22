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
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.4/govern-2.1.0-darwin-arm64.tar.gz"
      sha256 "b8be13a39c029b065ae09c20ba1c0ba6c293cea28504c07fbf68016d08bf6b6d"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.4/govern-2.1.0-darwin-x64.tar.gz"
      sha256 "2ab89966d1ef6a85155ed4e10f7349add629fb28248aee7578f1adca5d12999e"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.4/govern-2.1.0-linux-arm64.tar.gz"
      sha256 "b6ecb7767f132a18583120b6707e43752329eeeebb498b3cd98ef4e9d4a4f181"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.4/govern-2.1.0-linux-x64.tar.gz"
      sha256 "e43038057e110d0e7b91eb230900cf9e0ac574699a60d1b61f8ea13271447faa"
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
