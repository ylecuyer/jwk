describe JWK::OctKey do
  let(:jwk) do
    File.read("spec/support/oct.json")
  end

  describe '#to_pem' do
    it 'raises' do
      key = JWK::Key.from_json(jwk)
      expect { key.to_pem }.to raise_error(NotImplementedError)
    end
  end

  describe '#to_s' do
    it 'returns the key' do
      key = JWK::Key.from_json(jwk)
      expect(key.to_s).to eq 'hello world'
    end
  end

  describe '#to_openssl_key' do
    it 'raises' do
      key = JWK::Key.from_json(jwk)
      expect { key.to_openssl_key }.to raise_error(NotImplementedError)
    end
  end

  describe '#to_json' do
    it 'responds with the JWK JSON key' do
      key = JWK::Key.from_json(jwk)
      expect(JSON.parse(key.to_json)).to eq JSON.parse(jwk)
    end
  end

  describe '#kty' do
    it 'equals oct' do
      key = JWK::Key.from_json(jwk)
      expect(key.kty).to eq 'oct'
    end
  end

  describe '#public?' do
    it 'is true' do
      key = JWK::Key.from_json(jwk)
      expect(key.public?).to be_truthy
    end
  end

  describe '#private?' do
    it 'is true' do
      key = JWK::Key.from_json(jwk)
      expect(key.private?).to be_truthy
    end
  end
end
