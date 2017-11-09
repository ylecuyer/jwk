module JWK
  class Key
    class << self
      def from_json(json)
        key = JSON.parse(json)
        validate_kty!(key['kty'])

        case key['kty']
        when 'EC'
          ECKey.new(key)
        when 'RSA'
          RSAKey.new(key)
        when 'oct'
          OctKey.new(key)
        end
      end

      def validate_kty!(kty)
        unless %w[EC RSA oct].include?(kty)
          raise JWK::InvalidKey, "The provided JWK has an unknown \"kty\" value: #{kty}."
        end
      end
    end

    def to_json
      @key.to_json
    end

    %w[kty use key_ops alg kid x5u x5c x5t].each do |part|
      define_method(part) do
        @key[part]
      end
    end

    def x5t_s256
      @key['x5t#S256']
    end

    protected

    def decode_base64_int(str)
      unspaced = str.gsub(/[[:space:]]/, '')
      binary_n = Base64.urlsafe_decode64(unspaced)

      binary_n.chars.inject(0) do |val, char|
        (val << 8) | char[0].ord
      end
    end

    def pem_base64(content)
      Base64.strict_encode64(content).scan(/.{1,64}/).join("\n")
    end

    def generate_pem(header, asn)
      "-----BEGIN #{header} KEY-----\n" +
        pem_base64(asn) +
        "\n-----END #{header} KEY-----\n"
    end
  end
end
