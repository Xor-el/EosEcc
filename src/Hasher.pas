unit Hasher;

interface

uses
  ClpDigestUtilities,
  ClpCryptoLibTypes;

type
  THasher = class sealed(TObject)

  public
    class function SHA1(const data: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;
    class function SHA256(const data: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;
    class function SHA512(const data: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;
    class function RIPEMD160(const data: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;
  end;

implementation

{ THasher }

class function THasher.SHA1(const data: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := TDigestUtilities.CalculateDigest('SHA-1', data);
end;

class function THasher.SHA256(const data: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := TDigestUtilities.CalculateDigest('SHA-256', data);
end;

class function THasher.SHA512(const data: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := TDigestUtilities.CalculateDigest('SHA-512', data);
end;

class function THasher.RIPEMD160(const data: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := TDigestUtilities.CalculateDigest('RIPEMD160', data);
end;

end.
