# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.7.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.5.0/agentsafe-0.7.0-darwin-arm64.tar.gz"
      sha256 "c8f3ec38b8f899a6d0df866aa185b34eaf1f92805e2e893411c1af60c547ae84"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.5.0/agentsafe-0.7.0-darwin-x64.tar.gz"
      sha256 "87127ef14b2503c455585840b3604243f88942a9a81aa8df00951a413095bc73"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.5.0/agentsafe-0.7.0-linux-arm64.tar.gz"
      sha256 "c61886a9fc083310d04c5ad2c0ddbf6da8891f6e98fbc751a85ab0b109347a73"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.5.0/agentsafe-0.7.0-linux-x64.tar.gz"
      sha256 "8e6203c23b17bb869c73c9d21e70d29b0033414ca7dcc98a3392eee86caf5e56"
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
