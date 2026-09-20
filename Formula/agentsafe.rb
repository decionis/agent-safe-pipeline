# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.2.1"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.1/agentsafe-0.2.1-darwin-arm64.tar.gz"
      sha256 "a62bb65073b22b1027ae906f95d2846be21de066806b20808a0bbf4019d1e04b"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.1/agentsafe-0.2.1-darwin-x64.tar.gz"
      sha256 "db900c46970a770387f47b8d5d43442e0f90374422171c74ef194d51cb263b77"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.1/agentsafe-0.2.1-linux-arm64.tar.gz"
      sha256 "cf3c14e814757e66e8d41c63b2935760057c8a9e1d67856f0f1dc4d475800aa6"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.1/agentsafe-0.2.1-linux-x64.tar.gz"
      sha256 "445bf7f82be43a7474e75445941f7e865340c24a48c03fa3cca510a8412fde89"
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
