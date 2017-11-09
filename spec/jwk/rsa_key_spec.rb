describe JWK::RSAKey do
  let(:private_jwk) do
    File.read("spec/support/rsa_private.json")
  end

  let(:public_jwk) do
    File.read("spec/support/rsa_public.json")
  end

  let(:partial_jwk) do
    File.read("spec/support/rsa_partial.json")
  end

  let(:private_pem) do
    File.read("spec/support/rsa_private.pem")
  end

  let(:public_pem) do
    File.read("spec/support/rsa_public.pem")
  end

  describe '#to_pem' do
    it 'converts private keys to the right format' do
      key = JWK::Key.from_json(private_jwk)
      expect(key.to_pem).to eq private_pem
    end

    it 'converts public keys keys to the right format' do
      key = JWK::Key.from_json(public_jwk)
      expect(key.to_pem).to eq public_pem
    end

    it 'fails on private keys with missing parameters' do
      key = JWK::Key.from_json(partial_jwk)
      expect { key.to_pem }.to raise_error NotImplementedError
    end
  end

  describe '#to_s' do
    it 'converts to pem' do
      key = JWK::Key.from_json(public_jwk)
      expect(key.to_s).to eq(key.to_pem)
    end
  end

  describe '#to_openssl_key' do
    it 'converts the private key to an openssl object' do
      key = JWK::Key.from_json(private_jwk)
      expect(key.to_openssl_key).to be_a OpenSSL::PKey::RSA
    end
  end

  describe '#to_json' do
    it 'responds with the JWK JSON key' do
      key = JWK::Key.from_json(private_jwk)
      expect(JSON.parse(key.to_json)).to eq JSON.parse(private_jwk)
    end
  end

  describe '#kty' do
    it 'equals RSA' do
      key = JWK::Key.from_json(private_jwk)
      expect(key.kty).to eq 'RSA'
    end
  end

  describe '#public?' do
    it 'is true' do
      key = JWK::Key.from_json(private_jwk)
      expect(key.public?).to be_truthy
    end
  end

  describe '#private?' do
    it 'is true for private keys' do
      key = JWK::Key.from_json(private_jwk)
      expect(key.private?).to be_truthy
    end

    it 'is false for public keys' do
      key = JWK::Key.from_json(public_jwk)
      expect(key.private?).to be_falsey
    end
  end

  describe '#x5t_s256' do
    it 'responds with the x5t#S256 element of the JWK' do
      key = JWK::Key.from_json('{"kty":"RSA","n":"1","e":"2","x5t#S256":"hello"}')
      expect(key.x5t_s256).to eq 'hello'
    end
  end
end
