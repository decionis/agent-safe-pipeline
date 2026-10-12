# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.4.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.7/agentsafe-0.4.0-darwin-arm64.tar.gz"
      sha256 "77c4d4e4189524cd1fa9f2b9dfefb5027a2cdafefdb691978cd4d6bece306aa9"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.7/agentsafe-0.4.0-darwin-x64.tar.gz"
      sha256 "2dd8affb028b6c0c43cd5c532de805fa8ae833335a6922f152916f4c6fbe01f6"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.7/agentsafe-0.4.0-linux-arm64.tar.gz"
      sha256 "76bcf5f9e2ac3f5459d9ff13e4bdef9b04a54a42a098e6a7a68bf4c338a9bd36"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.7/agentsafe-0.4.0-linux-x64.tar.gz"
      sha256 "3d3b8a8a7010d34b7cbd2b595d1fe3a68599cd345901dd9707b2ce23c432e340"
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
