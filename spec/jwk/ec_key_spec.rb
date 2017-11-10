describe JWK::ECKey do
  let(:private_jwk) do
    File.read('spec/support/ec_private.json')
  end

  let(:public_jwk) do
    File.read('spec/support/ec_public.json')
  end

  let(:private_pem) do
    File.read('spec/support/ec_private.pem')
  end

  describe '#initialize' do
    it 'raises with invalid parameters' do
      expect { JWK::Key.from_json('{"kty":"EC","crv":"P-256"}') }.to raise_error(JWK::InvalidKey)
    end
  end

  describe '#to_pem' do
    it 'converts private keys to the right format' do
      key = JWK::Key.from_json(private_jwk)
      expect(key.to_pem).to eq private_pem
    end

    it 'raises with public keys' do
      key = JWK::Key.from_json(public_jwk)
      expect { key.to_pem }.to raise_error NotImplementedError
    end
  end

  describe '#to_s' do
    it 'converts to pem' do
      key = JWK::Key.from_json(private_jwk)
      expect(key.to_s).to eq(key.to_pem)
    end
  end

  describe '#to_openssl_key' do
    it 'converts the private key to an openssl object' do
      key = JWK::Key.from_json(private_jwk)

      begin
        expect(key.to_openssl_key).to be_a OpenSSL::PKey::EC
      rescue Exception => e
        # This is expected to fail on old jRuby versions
        raise e unless defined?(JRUBY_VERSION)
      end
    end
  end

  describe '#to_json' do
    it 'responds with the JWK JSON key' do
      key = JWK::Key.from_json(private_jwk)
      expect(JSON.parse(key.to_json)).to eq JSON.parse(private_jwk)
    end
  end

  describe '#kty' do
    it 'equals EC' do
      key = JWK::Key.from_json(private_jwk)
      expect(key.kty).to eq 'EC'
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
end
