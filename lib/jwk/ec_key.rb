require 'jwk/key'

module JWK
  class ECKey < Key
    def initialize(key)
      @key = key
      validate
    end

    def public?
      true
    end

    def private?
      !@key['d'].nil?
    end

    def validate
      unless @key['x'] && @key['y'] && ['P-256', 'P-384', 'P-521'].include?(@key['crv'])
        raise JWK::InvalidKey, 'Invalid EC key.'
      end
    end

    def to_pem
      raise NotImplementedError, 'Cannot convert an EC public key to PEM.' unless private?

      asn = ASN1.ec_private_key(crv, d, x, y)
      generate_pem('EC PRIVATE', asn)
    end

    def to_openssl_key
      OpenSSL::PKey.read(to_pem)
    end

    def to_s
      to_pem
    end

    def crv
      @key['crv']
    end

    %w[d x y].each do |part|
      define_method(part) do
        decode_base64_int(@key[part]) if @key[part]
      end
    end

    class << self
      def from_openssl(k)
        pb = k.public_key.to_bn.to_s(16)
        raise NotImplementedError, 'Cannot convert EC compressed public key' unless pb[0..1] == '04'

        pb = pb[2..-1]
        x = pb[0...pb.length / 2].scan(/.{2}/).map { |n| n.to_i(16).chr }.join
        y = pb[pb.length / 2..-1].scan(/.{2}/).map { |n| n.to_i(16).chr }.join

        names = { 'secp256r1' => 'P-256', 'secp384r1' => 'P-384', 'secp521r1' => 'P-521' }
        crv = names[k.group.curve_name]

        raise NotImplementedError, "Unsupported EC curve type #{k.group.curve_name}" unless crv

        key = {
          'kty' => 'EC',
          'crv' => crv,
          'd' => encode_base64_int(k.private_key.to_i),
          'x' => Base64.urlsafe_encode64(x),
          'y' => Base64.urlsafe_encode64(y)
        }

        new(key)
      end
    end
  end
end
