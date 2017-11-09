require 'jwk/key'

module JWK
  class OctKey < Key
    def initialize(key)
      @key = key
      validate
    end

    def public?
      true
    end

    def private?
      true
    end

    def validate
      raise JWK::InvalidKey, 'Invalid RSA key.' unless @key['k']
    end

    def to_pem
      raise NotImplementedError, 'Oct Keys cannot be converted to PEM.'
    end

    def to_openssl_key
      raise NotImplementedError, 'Oct Keys cannot be converted to OpenSSL::PKey.'
    end

    def to_s
      k
    end

    def k
      Base64.urlsafe_decode64(@key['k'])
    end
  end
end
