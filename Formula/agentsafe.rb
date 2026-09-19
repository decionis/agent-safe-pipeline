# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.2.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.0/agentsafe-0.2.0-darwin-arm64.tar.gz"
      sha256 "494da30830526ce67859dab09760bb7208605c8fa193f51b1de7c35b30a40af6"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.0/agentsafe-0.2.0-darwin-x64.tar.gz"
      sha256 "4aaf8c0201af10559af376d7b1bd6b9e1e5d8f551fc0bf76e86009cd27402b84"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.0/agentsafe-0.2.0-linux-arm64.tar.gz"
      sha256 "c3652a182a3140a0c61009c441ed00f8fa712316e67149e2b12dbdeb9fe395c5"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.0/agentsafe-0.2.0-linux-x64.tar.gz"
      sha256 "edc1b7143b215a2008af85780e3977da2ef11bfc44734fcb888cfe41c74c7c4c"
    end
  end

  def install
    libexec.install Dir["*"]
    bin.install_symlink libexec/"agentsafe"
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/agentsafe version").strip
    # The doctor passes offline against the demo authority: the binary, the
    # configuration and the evidence settings are checked, the network is not.
    assert_match "Ready to govern.", shell_output("#{bin}/agentsafe doctor --upstream http://127.0.0.1:1 --no-network")
  end
end
