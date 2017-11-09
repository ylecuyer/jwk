module JWK
  class ASN1
    class << self
      def rsa_public_key(n, e)
        pubkey = bit_string(sequence(integer(n), integer(e)))
        sequence(rsa_header, pubkey)
      end

      def rsa_private_key(*args)
        raise ArgumentError('Some pieces missing for RSA Private Key') unless args.length == 8
        sequence(integer(0), *args.map { |n| integer(n) })
      end

      def ec_private_key(crv, d, x, y)
        _, raw_x = raw_integer_encoding(x)
        _, raw_y = raw_integer_encoding(y)

        object_id = object_id_for_crv(crv)

        sequence(
          integer(1),
          integer_octet_string(d),
          context_specific(true, 0, object_id),
          context_specific(true, 1, bit_string("\x04#{raw_x}#{raw_y}"))
        )
      end

      private

      def object_id_for_crv(crv)
        case crv
        when 'P-256'
          "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07"
        when 'P-384'
          "\x06\x05\x2B\x81\x04\x00\x22"
        when 'P-521'
          "\x06\x05\x2B\x81\x04\x00\x23"
        end
      end

      def rsa_header
        "\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00".force_encoding('ASCII-8BIT')
      end

      def bit_string(data)
        "\x03" + asn_length(data.length + 1) + "\x00" + data
      end

      def sequence(*items)
        data = items.join
        "\x30" + asn_length(data.length) + data
      end

      def integer(n)
        len, data = raw_integer_encoding(n)

        if data[0].ord & 0x80 != 0
          data = "\x00" + data
          len += 1
        end

        "\x02" + asn_length(len) + data
      end

      def integer_octet_string(n)
        len, data = raw_integer_encoding(n)
        "\x04" + asn_length(len) + data
      end

      def asn_length(n)
        if n > 127
          self_len, data = raw_integer_encoding(n)
          self_len |= 0x80
          self_len.chr + data
        else
          n.chr
        end
      end

      def raw_integer_encoding(n)
        # find out how many octets are required to encode it
        num_octets = n.zero? ? 1 : (Math.log(n) / Math.log(256)).to_i + 1

        # encode the low num_octets bytes of the integer.
        shifted = n << 8
        data = Array.new(num_octets) do
          ((shifted >>= 8) & 0xFF).chr
        end.join.reverse

        [num_octets, data]
      end

      def context_specific(structured, tag, content)
        tag |= 0x80
        tag |= 0x20 if structured

        tag.chr + asn_length(content.length) + content.force_encoding('ASCII-8BIT')
      end
    end
  end
end
