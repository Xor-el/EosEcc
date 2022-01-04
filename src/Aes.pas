unit Aes;

interface

uses
  SysUtils,
  DateUtils,
  KeyUtils,
  Hasher,
  EosPrivateKey,
  EosPublicKey,
  ClpIParametersWithIV,
  ClpCipherUtilities,
  ClpParameterUtilities,
  ClpParametersWithIV,
  ClpIBufferedCipher,
  ClpConverters,
  ClpArrayUtils,
  ClpCryptoLibTypes;

type
  CryptData = record
  public
    Nonce: Int64;
    &Message: TCryptoLibByteArray;
    Checksum: UInt32;

    constructor Create(ANonce: Int64; const AMessage: TCryptoLibByteArray;
      AChecksum: UInt32);
  end;

type
  TAes = class sealed(TObject)
  strict private
    class var

      FUniqueNonceEntropy: Int64;

    class constructor Aes();
    class function UniqueNonce(): string; static;
    class function AesEncrypt(const AMessage, AKey, AIV: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;
    class function AesDecrypt(const AMessage, AKey, AIV: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;
    class function Crypt(const APrivateKey: IEosPrivateKey;
      const APublicKey: IEosPublicKey; const ANonce: string;
      const AMessage: TCryptoLibByteArray; const AChecksum: string = '')
      : CryptData; static;

  public
    class function Encrypt(const APrivateKey: IEosPrivateKey;
      const APublicKey: IEosPublicKey; const AMessage: TCryptoLibByteArray;
      const ANonce: string = ''): CryptData; static;
    class function Decrypt(const APrivateKey: IEosPrivateKey;
      const APublicKey: IEosPublicKey; const ANonce: string;
      const AMessage: TCryptoLibByteArray; const AChecksum: string)
      : TCryptoLibByteArray; static;

  end;

implementation

{ TAes }

class constructor TAes.Aes;
var
  b: TCryptoLibByteArray;
begin
  b := TKeyUtils.RandomBytes(2);
  FUniqueNonceEntropy := (b[0] shl 8 or b[1]);
end;

class function TAes.AesEncrypt(const AMessage, AKey, AIV: TCryptoLibByteArray)
  : TCryptoLibByteArray;
var
  KeyParametersWithIV: IParametersWithIV;
  cipher: IBufferedCipher;
begin
  if (AMessage = Nil) then
  begin
    raise EArgumentNilException.Create('Plain Text Missing');
  end;

  cipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
  KeyParametersWithIV := TParametersWithIV.Create
    (TParameterUtilities.CreateKeyParameter('AES', AKey), AIV);
  cipher.Init(True, KeyParametersWithIV);
  Result := cipher.DoFinal(AMessage);
end;

class function TAes.AesDecrypt(const AMessage, AKey, AIV: TCryptoLibByteArray)
  : TCryptoLibByteArray;
var
  KeyParametersWithIV: IParametersWithIV;
  cipher: IBufferedCipher;
begin
  if (AMessage = Nil) then
  begin
    raise EArgumentNilException.Create('Cipher Text Missing');
  end;

  cipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
  KeyParametersWithIV := TParametersWithIV.Create
    (TParameterUtilities.CreateKeyParameter('AES', AKey), AIV);
  cipher.Init(False, KeyParametersWithIV);
  Result := cipher.DoFinal(AMessage);
end;

class function TAes.Crypt(const APrivateKey: IEosPrivateKey;
  const APublicKey: IEosPublicKey; const ANonce: string;
  const AMessage: TCryptoLibByteArray; const AChecksum: string): CryptData;
var
  LNonce: Int64;
  Check, LChecksum: UInt32;
  S, EBuf, EncryptionKey, IV, Key, Temp, LMessage: TCryptoLibByteArray;
begin
  if (APrivateKey = Nil) then
  begin
    raise EArgumentNilException.Create('Private Key is required');
  end;

  if (APublicKey = Nil) then
  begin
    raise EArgumentNilException.Create('Public Key is required');
  end;

  if (string.IsNullOrWhiteSpace(ANonce)) then
  begin
    raise EArgumentException.Create('Nonce is required');
  end;

  LNonce := StrToInt64(Trim(ANonce));
  S := APrivateKey.GetSharedSecret(APublicKey);
  EBuf := TConverters.ReadUInt64AsBytesLE(LNonce);
  EBuf := TArrayUtils.Concatenate(EBuf, S);
  EncryptionKey := THasher.SHA512(EBuf);
  IV := System.Copy(EncryptionKey, 32, 16);
  Key := System.Copy(EncryptionKey, 0, 32);
  // Check is first 64 bit of sha256 hash treated as uint64_t truncated to 32 bits.
  Temp := System.Copy(THasher.SHA256(EncryptionKey), 0, 4);
  Check := TConverters.ReadBytesAsUInt32LE(PByte(Temp), 0);
  if (not string.IsNullOrWhiteSpace(AChecksum)) then
  begin
    LChecksum := StrToUInt(Trim(AChecksum));
    if (Check <> LChecksum) then
    begin
      raise Exception.Create('Invalid Key');
    end;
    LMessage := AesDecrypt(AMessage, Key, IV);
  end
  else
  begin
    LMessage := AesEncrypt(AMessage, Key, IV);
  end;
  Result := CryptData.Create(LNonce, LMessage, Check);
end;

class function TAes.Decrypt(const APrivateKey: IEosPrivateKey;
  const APublicKey: IEosPublicKey; const ANonce: string;
  const AMessage: TCryptoLibByteArray; const AChecksum: string)
  : TCryptoLibByteArray;
begin
  Result := Crypt(APrivateKey, APublicKey, ANonce, AMessage, AChecksum).Message;
end;

class function TAes.Encrypt(const APrivateKey: IEosPrivateKey;
  const APublicKey: IEosPublicKey; const AMessage: TCryptoLibByteArray;
  const ANonce: string): CryptData;
var
  LNonce: string;
begin
  LNonce := ANonce;
  if (string.IsNullOrWhiteSpace(LNonce)) then
  begin
    LNonce := UniqueNonce();
  end;
  Result := Crypt(APrivateKey, APublicKey, LNonce, AMessage);
end;

class function TAes.UniqueNonce: string;
var
  Entropy, UnixTime: Int64;
begin
  UnixTime := DateUtils.MilliSecondsBetween(Now,
    TTimeZone.Local.ToUniversalTime(EncodeDateTime(1970, 1, 1, 0, 0, 0, 0)));
  System.Inc(FUniqueNonceEntropy);
  Entropy := FUniqueNonceEntropy mod $FFFF;
  UnixTime := (UnixTime shl 16) or Entropy;
  Result := IntToStr(UnixTime);
end;

{ CryptData }

constructor CryptData.Create(ANonce: Int64; const AMessage: TCryptoLibByteArray;
  AChecksum: UInt32);
begin
  Nonce := ANonce;
  &Message := AMessage;
  Checksum := AChecksum;
end;

end.
