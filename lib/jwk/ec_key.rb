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
  end
end
