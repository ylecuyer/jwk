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
      begin
        key = OpenSSL::PKey::EC.new('secp384r1')
        key.generate_key
        jwk = JWK::Key.from_openssl(key)

        expect(jwk).to be_a JWK::ECKey
      rescue NameError => e
        raise e unless defined?(JRUBY_VERSION)
      end
    end

    # jRuby 9k OpenSSL generates a bad PEM file with private key only, skipping
    # the public part. This is in contrast with all other OpenSSL implementations.
    # And it makes this test fail.
    it 'creates an ECKey for EC keys that resolves to the same parameters' do
      begin
        key = OpenSSL::PKey::EC.new('secp384r1')
        key.generate_key
        jwk = JWK::Key.from_openssl(key)

        unless defined?(JRUBY_VERSION)
          expect(jwk.to_pem).to eq key.to_pem
        end
      rescue NameError => e
        raise e unless defined?(JRUBY_VERSION)
      end
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
