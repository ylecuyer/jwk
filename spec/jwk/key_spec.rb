describe JWK::Key do
  describe '.from_json' do
    it 'raises for invalid kty' do
      expect { JWK::Key.from_json('{"kty":"my-key-type"}') }.to raise_error JWK::InvalidKey
    end
  end
end
