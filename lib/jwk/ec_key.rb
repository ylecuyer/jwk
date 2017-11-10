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
        Utils.decode_ub64_int(@key[part]) if @key[part]
      end
    end

    class << self
      def from_openssl(k)
        x, y = coords_from_key(k)

        names = { 'secp256r1' => 'P-256', 'secp384r1' => 'P-384', 'secp521r1' => 'P-521' }
        crv = names[k.group.curve_name]

        raise NotImplementedError, "Unsupported EC curve type #{k.group.curve_name}" unless crv

        new('kty' => 'EC',
            'crv' => crv,
            'd' => Utils.encode_ub64_int(k.private_key.to_i), 'x' => x, 'y' => y)
      end

      private

      def coords_from_key(key)
        pb = key.public_key.to_bn.to_s(16)

        raise NotImplementedError, 'Cannot convert EC compressed public key' unless pb[0..1] == '04'

        decode_uncompressed_coords(pb[2..-1])
      end

      def decode_uncompressed_coords(pb)
        coords = [pb[0...pb.length / 2], pb[pb.length / 2..-1]]
        coords.map { |c| Base64.urlsafe_encode64(Utils.hex_string_to_binary(c)) }
      end
    end
  end
end
