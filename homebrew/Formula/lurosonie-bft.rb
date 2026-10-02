# typed: false
# frozen_string_literal: true

class LurosonieBft < Formula
  desc "Slura chain node (Lurosonie-BFT) – portable EVM-compatible node"
  homepage "https://vylte-finuka.com/en-EN/ecosystem/vyft-slura"
  license "Proprietary"
  version "1.1.0"

  url "https://github.com/\( {REPO}/releases/download/ \){TAG}/lurosonie-bft-1.1.0.tar.gz"
  sha256 "de02c0bfe13c03559cceaf1d3789b1e3c4e251c8147963727dc3805586254b7a"

  depends_on "openssl@3" => :recommended

  def install
    bin.install "lurosonie-bft"
    (etc/"lurosonie-bft").install ".env.example" if File.exist?(".env.example")
  end

  def caveats
    <<\~EOS
      Configuration recommandée :
        cp #{etc}/lurosonie-bft/.env.example \~/.lurosonie-bft.env

      Démarrage :
        lurosonie-bft --help
    EOS
  end

  test do
    assert_predicate bin/"lurosonie-bft", :exist?
    system "#{bin}/lurosonie-bft", "--help"
  end
end
