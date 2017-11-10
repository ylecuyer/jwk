describe JWK::Key do
  describe '.from_json' do
    it 'raises for invalid kty' do
      expect { JWK::Key.from_json('{"kty":"my-key-type"}') }.to raise_error JWK::InvalidKey
    end
  end

  describe '.from_openssl' do
    it 'creates an RSAKey for RSA keys' do
      key = OpenSSL::PKey::RSA.new(2048)
      jwk = JWK::Key.from_openssl(key)

      expect(jwk).to be_a JWK::RSAKey
    end

    it 'creates an RSAKey for RSA keys that resolves to the same parameters' do
      key = OpenSSL::PKey::RSA.new(2048)
      jwk = JWK::Key.from_openssl(key)

      expect(jwk.to_pem).to eq key.to_pem
    end

    it 'creates an RSAKey for RSA public keys that resolves to the same parameters' do
      key = OpenSSL::PKey::RSA.new(2048).public_key
      jwk = JWK::Key.from_openssl(key)

      expect(jwk.to_pem).to eq key.to_pem
    end

    it 'creates an ECKey for EC keys' do
      key = OpenSSL::PKey::EC.new('secp384r1')
      key.generate_key
      jwk = JWK::Key.from_openssl(key)

      expect(jwk).to be_a JWK::ECKey
    end

    it 'creates an ECKey for EC keys that resolves to the same parameters' do
      key = OpenSSL::PKey::EC.new('secp384r1')
      key.generate_key
      jwk = JWK::Key.from_openssl(key)

      expect(jwk.to_pem).to eq key.to_pem
    end
  end

  describe '.from_pem' do
    it 'generates an RSAKey for RSA Keys' do
      pem = OpenSSL::PKey::RSA.new(2048).to_pem
      jwk = JWK::Key.from_pem(pem)

      expect(jwk).to be_a JWK::RSAKey
    end
  end
end
