class VexaSca < Formula
  desc "Evidence-aware Software Composition Analysis, AST Reachability, SAST & Supply-Chain Firewall"
  homepage "https://vexasec.io/sca"
  version "1.3.7"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/noviqtechnologies/vexa-sca/releases/download/v#{version}/vexa-sca-darwin-arm64.tar.gz"
      sha256 "96e25b5227f181cdeb5f6e6f678ac9bd47ca94dbacd9c3464881d3c5b05faf55"
    else
      url "https://github.com/noviqtechnologies/vexa-sca/releases/download/v#{version}/vexa-sca-darwin-x86_64.tar.gz"
      sha256 "c18521ea1da1763b72076c8e46849010f5a58256a9d62c2a0eedaf3e8c92f18b"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/noviqtechnologies/vexa-sca/releases/download/v#{version}/vexa-sca-linux-arm64.tar.gz"
      sha256 "0f529f07a6f4585733af6c1e81e9593f8afc9700bfc18468f663b3bfc2ce4b8e"
    else
      url "https://github.com/noviqtechnologies/vexa-sca/releases/download/v#{version}/vexa-sca-linux-x86_64.tar.gz"
      sha256 "058fc12406e7124c31e8451b779d1901d41d509e5784ad53d466da2d225f8a0b"
    end
  end

  def install
    bin.install "vexa-sca"
    bin.install "vexa" if File.exist?("vexa")
    bin.install "sca" if File.exist?("sca")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/vexa-sca --version")
  end
end
