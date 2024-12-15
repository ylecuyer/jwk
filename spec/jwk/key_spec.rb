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

    it 'creates an ECKey for EC private keys' do
      begin
        key = OpenSSL::PKey::EC.generate('secp384r1')
        jwk = JWK::Key.from_openssl(key)

        expect(jwk).to be_a JWK::ECKey
      rescue NameError => e
        raise e unless defined?(JRUBY_VERSION)
      end
    end

    # jRuby 9k OpenSSL generates a bad PEM file with private key only, skipping
    # the public part. This is in contrast with all other OpenSSL implementations.
    # And it makes this test fail.
    it 'creates an ECKey for EC private keys that resolves to the same parameters' do
      begin
        key = OpenSSL::PKey::EC.generate('secp384r1')
        jwk = JWK::Key.from_openssl(key)

        expect(jwk.to_pem).to eq key.to_pem unless defined?(JRUBY_VERSION)
      rescue NameError => e
        raise e unless defined?(JRUBY_VERSION)
      end
    end

    it 'creates an ECKey for EC public keys' do
      begin
        key = OpenSSL::PKey::EC.generate('secp384r1')
        jwk = JWK::Key.from_openssl(key.public_key)

        expect(jwk).to be_a JWK::ECKey
      rescue NameError => e
        raise e unless defined?(JRUBY_VERSION)
      end
    end

    it 'creates an ECKey for EC public keys that resolves to the same parameters' do
      begin
        key = OpenSSL::PKey::EC.generate('secp384r1')
        jwk = JWK::Key.from_openssl(key.public_key)

        expect(jwk.to_openssl_key).to eq key.public_key
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

    it 'generates an ECKey for EC Keys' do
      begin
        pem = OpenSSL::PKey::EC.generate('prime256v1').to_pem
        jwk = JWK::Key.from_pem(pem)

        expect(jwk).to be_a JWK::ECKey
      rescue ArgumentError, NameError => e
        raise e unless defined?(JRUBY_VERSION)
      end
    end
  end
end
