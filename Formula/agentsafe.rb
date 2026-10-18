# The AgentSafe formula, rendered by scripts/RenderHomebrewFormula.mjs from a
# release's SHA256SUMS. It installs the executable the release built for this
# platform (on Intel macOS, a launcher with the pinned Node release beside
# it); nothing is compiled and no Node needs to be installed. The same
# archive is what packaging/install.sh downloads and verifies.
class Agentsafe < Formula
  desc "Execution-authority gateway: intercepts consequential actions and enforces Decionis verdicts"
  homepage "https://github.com/decionis/agent-safe-pipeline"
  version "0.5.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.8/agentsafe-0.5.0-darwin-arm64.tar.gz"
      sha256 "f377101df8b9843da278a06cd1e5741753842f49216eac7387252577b2047c26"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.8/agentsafe-0.5.0-darwin-x64.tar.gz"
      sha256 "23c88bd4931132519a892a0688c4d0a5b1fe5d2fd48c90d7052211016ac5c993"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.8/agentsafe-0.5.0-linux-arm64.tar.gz"
      sha256 "1bc6fad9797aec3db6aaa213e613a9d5286a9495223a0a296542567936322464"
    end
    on_intel do
      url "https://github.com/decionis/agent-safe-pipeline/releases/download/v0.3.8/agentsafe-0.5.0-linux-x64.tar.gz"
      sha256 "5e3fe359a901d94f93a2656d50f33cf6113173fdf9499013b1b40ed0637cb84f"
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
