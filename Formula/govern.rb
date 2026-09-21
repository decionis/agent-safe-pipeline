# The govern formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the static binary the release built for
# this platform; nothing is compiled and no toolchain is needed. The same
# archive is what govern/install.sh downloads and verifies.
class Govern < Formula
  desc "Workflow gate: one Decionis verdict before a CI step runs, with a signed record"
  homepage "https://github.com/decionis/agent-safe-pipeline/tree/master/govern"
  version "2.0.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.3/govern-2.0.0-darwin-arm64.tar.gz"
      sha256 "5386efc796768dd27f05919ed7731674ea28cbb302b3b94c3758a3babfb2774a"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.3/govern-2.0.0-darwin-x64.tar.gz"
      sha256 "133f64715683c6874823d7cf2b5170cfdc0ef099fbcda7f68271d8891e823b02"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.3/govern-2.0.0-linux-arm64.tar.gz"
      sha256 "fe1532a74db7649ef7be7f63863152bd28ca4bd9b03fe910f9ac639c035e2eac"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.3/govern-2.0.0-linux-x64.tar.gz"
      sha256 "3b5d8a79cd50d4333abab3e6e994f7e9fd455be464d5245116d19dd03c9edad1"
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
