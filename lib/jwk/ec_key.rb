require 'jwk/key'

module JWK
  class ECKey < Key
    CURVE_NAMES = {
      'prime256v1' => 'P-256',
      'secp384r1' => 'P-384',
      'secp521r1' => 'P-521'
    }.freeze

    COORD_SIZE = {
      'P-256' => 32,
      'P-384' => 48,
      'P-521' => 64
    }.freeze

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

      asn = ASN1.ec_private_key(crv, d, raw_public_key)
      generate_pem('EC PRIVATE', asn)
    end

    def to_openssl_key
      if private?
        OpenSSL::PKey.read(to_pem)
      else
        group = OpenSSL::PKey::EC::Group.new(self.class::CURVE_NAMES.key(crv))
        OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(raw_public_key.unpack("H*")[0], 16))
      end
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

    def raw_public_key
      raw_x = Utils.int_to_binary(x)
      raw_y = Utils.int_to_binary(y)

      raw_x = pad_coord_for_crv(crv, raw_x)
      raw_y = pad_coord_for_crv(crv, raw_y)

      "\x04#{raw_x}#{raw_y}"
    end

    class << self
      def from_openssl(k)
        if k.is_a? OpenSSL::PKey::EC::Point
          from_openssl_public(k)
        else
          from_openssl_private(k)
        end
      end

      private

      def from_openssl_private(k)
        x, y = coords_from_point(k.public_key)

        crv = CURVE_NAMES[k.group.curve_name]

        raise NotImplementedError, "Unsupported EC curve type #{k.group.curve_name}" unless crv

        new('kty' => 'EC',
            'crv' => crv,
            'd' => Utils.encode_ub64_int(k.private_key.to_i), 'x' => x, 'y' => y)
      end

      def from_openssl_public(k)
        x, y = coords_from_point(k)

        crv = CURVE_NAMES[k.group.curve_name]

        raise NotImplementedError, "Unsupported EC curve type #{k.group.curve_name}" unless crv

        new('kty' => 'EC',
            'crv' => crv,
            'x' => x, 'y' => y)
      end

      def coords_from_point(point)
        pb = point.to_bn.to_s(16)

        raise NotImplementedError, 'Cannot convert EC compressed public key' unless pb[0..1] == '04'

        decode_uncompressed_coords(pb[2..-1])
      end

      def decode_uncompressed_coords(pb)
        coords = [pb[0...pb.length / 2], pb[pb.length / 2..-1]]
        coords.map { |c| Base64.urlsafe_encode64(Utils.hex_string_to_binary(c)) }
      end
    end

    private

    def pad_coord_for_crv(crv, coord)
      coord.rjust(self.class::COORD_SIZE[crv], "\x00")
    end
  end
end
