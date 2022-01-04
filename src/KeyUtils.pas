unit KeyUtils;

interface

uses
  SysUtils,
  Hasher,
  CustomAssert,
  ClpArrayUtils,
  ClpEncoders,
  ClpConverters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  TKeyUtils = class sealed(TObject)

  class var

    FSecureRandom: ISecureRandom;

  public

    class function CheckEncode(const keyBuffer: TCryptoLibByteArray;
      const keyType: string = ''): string; static;
    class function CheckDecode(const keyString: string;
      const keyType: string = ''): TCryptoLibByteArray; static;
    class function RandomBytes(ACount: Int32): TCryptoLibByteArray; static;

    class constructor KeyUtils();

  end;

implementation

{ TKeyUtils }

class function TKeyUtils.CheckDecode(const keyString: string;
  const keyType: string): TCryptoLibByteArray;
var
  buffer, checksum, key, newCheck, check: TCryptoLibByteArray;
  a, b: string;
begin
  TCustomAssert.Pass(not string.IsNullOrEmpty(keyString),
    'private key expected');
  buffer := TBase58.Decode(keyString);
  checksum := System.Copy(buffer, System.Length(buffer) - 4, 4);
  key := System.Copy(buffer, 0, System.Length(buffer) - 4);
  if (keyType = 'sha256x2') then
  begin
    // legacy
    // WIF (legacy)
    newCheck := System.Copy(THasher.SHA256(THasher.SHA256(key)), 0, 4);
  end
  else
  begin
    check := System.Copy(key);
    if (not string.IsNullOrWhiteSpace(keyType)) then
    begin
      check := TArrayUtils.Concatenate(check,
        TConverters.ConvertStringToBytes(keyType, TEncoding.UTF8));
    end;
    newCheck := System.Copy(THasher.RIPEMD160(check), 0, 4); // PVT
  end;

  a := THex.Encode(checksum);
  b := THex.Encode(newCheck);

  if (a <> b) then
  begin
    raise Exception.Create
      (SysUtils.Format('Invalid checksum,  "%s" <> "%s"', [a, b]));
  end;

  Result := key
end;

class function TKeyUtils.CheckEncode(const keyBuffer: TCryptoLibByteArray;
  const keyType: string): string;
var
  checksum, check: TCryptoLibByteArray;
begin
  if (keyBuffer = Nil) then
  begin
    raise EArgumentNilException.Create('keyBuffer cannot be Null');
  end;
  if (keyType = 'sha256x2') then
  begin
    // legacy
    checksum := System.Copy(THasher.SHA256(THasher.SHA256(keyBuffer)), 0, 4);
    Result := TBase58.Encode(TArrayUtils.Concatenate(keyBuffer, checksum));
    Exit;
  end
  else
  begin
    check := System.Copy(keyBuffer);
    if (not string.IsNullOrWhiteSpace(keyType)) then
    begin
      check := TArrayUtils.Concatenate(check,
        TConverters.ConvertStringToBytes(keyType, TEncoding.UTF8));
    end;
    checksum := System.Copy(THasher.RIPEMD160(check), 0, 4);
    Result := TBase58.Encode(TArrayUtils.Concatenate(keyBuffer, checksum));
  end;
end;

class constructor TKeyUtils.KeyUtils;
begin
  FSecureRandom := TSecureRandom.Create();
end;

class function TKeyUtils.RandomBytes(ACount: Int32): TCryptoLibByteArray;
begin
  Result := TSecureRandom.GetNextBytes(FSecureRandom, ACount);
end;

end.
