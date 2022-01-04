unit Hasher;

interface

uses
  ClpDigestUtilities,
  ClpCryptoLibTypes;

type
  THasher = class sealed(TObject)

  public
    class function SHA1(data: TCryptoLibByteArray): TCryptoLibByteArray; static;
    class function SHA256(data: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;
    class function SHA512(data: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;
    class function RIPEMD160(data: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;
  end;

implementation

{ THasher }

class function THasher.SHA1(data: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := TDigestUtilities.CalculateDigest('SHA-1', data);
end;

class function THasher.SHA256(data: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := TDigestUtilities.CalculateDigest('SHA-256', data);
end;

class function THasher.SHA512(data: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := TDigestUtilities.CalculateDigest('SHA-512', data);
end;

class function THasher.RIPEMD160(data: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := TDigestUtilities.CalculateDigest('RIPEMD160', data);
end;

end.
