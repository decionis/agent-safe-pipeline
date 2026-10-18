# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.6.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.4.0/agentsafe-0.6.0-darwin-arm64.tar.gz"
      sha256 "11ec9126e4b1e6cfe0c011ff780da8c24e6f4de9052eb1a119fc542d6d75e75f"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.4.0/agentsafe-0.6.0-darwin-x64.tar.gz"
      sha256 "b637581392740c1d7f3e9e691a4cb13cca22b189eefc375fc41beaeffc971856"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.4.0/agentsafe-0.6.0-linux-arm64.tar.gz"
      sha256 "20232c743b3f6bceebf98bfe67e45fca07bf127cb4cd242c6cc66e695f247c63"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.4.0/agentsafe-0.6.0-linux-x64.tar.gz"
      sha256 "6798e5d511366860698f51c17a4c588e330a208b99b247f1a185cd1bd6c7eab2"
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
