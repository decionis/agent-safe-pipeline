# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.2.3"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.3/agentsafe-0.2.3-darwin-arm64.tar.gz"
      sha256 "c13f46256275c818c4cbe4cf6bb190a39ce944b4a6921d9d0e558bad4f4dc157"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.3/agentsafe-0.2.3-darwin-x64.tar.gz"
      sha256 "e7eb5ad946dd85c3784fea59d8ce9d2290262a8f21265ef8af3de8971f9a6033"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.3/agentsafe-0.2.3-linux-arm64.tar.gz"
      sha256 "f247519f3cd28bda365a706227f018016b46e803c0e01b3a633ae1b1f975b930"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.3/agentsafe-0.2.3-linux-x64.tar.gz"
      sha256 "3b21ac30c21205b3a28caa0a99cc7a91a468ab5a35f92b9e6da048b9a74f8790"
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
