unit EosCrypt;

interface

uses
  SysUtils,
  Aes,
  EosPublicKey,
  EosPrivateKey,
  ClpEncoders,
  ClpConverters,
  ClpCryptoLibTypes;

type
  EncryptionOptionalData = record
  public
    Memo: string;
    MaxSize: Int32;

    constructor Create(const AMemo: string; AMaxSize: Int32);
  end;

type

  DecryptionOptionalData = record
  public
    Memo: string;

    constructor Create(const AMemo: string);
  end;

type
  DeserializedData = record
  public
    Checksum: UInt32;
    Content: TCryptoLibByteArray;
    Nonce: Int64;

    constructor Create(AChecksum: UInt32; const AContent: TCryptoLibByteArray;
      ANonce: Int64);
  end;

type
  TEosCrypt = class sealed(TObject)

  strict private
  const
    Memo = 'TO DECRYPT: eos-encrypt' + AnsiChar(#10);

    class function PadLeft(const AInput: string; ATotalWidth: Int32;
      APadChar: Char): String; static;

    class function Encrypt(const APrivateKey: IEosPrivateKey;
      const APublicKey: IEosPublicKey; const AMessage: TCryptoLibByteArray;
      const AOptions: EncryptionOptionalData): string; overload; static;

    class function Decrypt(const APrivateKey: IEosPrivateKey;
      const APublicKey: IEosPublicKey; const AMessage: string;
      const AOptions: DecryptionOptionalData): string; overload; static;

  public
    class function Serialize(const ABuff: CryptData; const AMemo: string = Memo)
      : string; static;
    class function Deserialize(const AMessage: String;
      const AMemo: string = Memo): DeserializedData; static;

    class function Encrypt(const APrivateKey: string; const APublicKey: string;
      const AMessage: TCryptoLibByteArray;
      const AOptions: EncryptionOptionalData): string; overload; static;

    class function Decrypt(const APrivateKey: string; const APublicKey: string;
      const AMessage: string; const AOptions: DecryptionOptionalData): string;
      overload; static;
  end;

implementation

{ DeserializedData }

constructor DeserializedData.Create(AChecksum: UInt32;
  const AContent: TCryptoLibByteArray; ANonce: Int64);
begin
  Checksum := AChecksum;
  Content := AContent;
  Nonce := ANonce;
end;

{ TEosCrypt }

class function TEosCrypt.Encrypt(const APrivateKey: IEosPrivateKey;
  const APublicKey: IEosPublicKey; const AMessage: TCryptoLibByteArray;
  const AOptions: EncryptionOptionalData): string;
var
  LMemo: string;
  LMaxSize: Int32;
  LBuff: CryptData;
begin
  LMemo := AOptions.Memo;
  if (string.IsNullOrWhiteSpace(LMemo)) then
  begin
    LMemo := Memo;
  end;

  LMaxSize := AOptions.MaxSize;
  if (LMaxSize = 0) then
  begin
    LMaxSize := 256;
  end;
  LBuff := TAes.Encrypt(APrivateKey, APublicKey, AMessage);
  Result := Serialize(LBuff, LMemo);

  if ((LMaxSize <> -1) and (System.Length(Result) > LMaxSize)) then
  begin
    raise Exception.Create(SysUtils.Format('message too long (max %d chars)',
      [LMaxSize]));
  end;
end;

class function TEosCrypt.Encrypt(const APrivateKey, APublicKey: string;
  const AMessage: TCryptoLibByteArray;
  const AOptions: EncryptionOptionalData): string;
begin
  Result := Encrypt(TEosPrivateKey.FromString(APrivateKey),
    TEosPublicKey.FromString(APublicKey), AMessage, AOptions);
end;

class function TEosCrypt.Decrypt(const APrivateKey: IEosPrivateKey;
  const APublicKey: IEosPublicKey; const AMessage: string;
  const AOptions: DecryptionOptionalData): string;
var
  LMemo: string;
  LNonce: Int64;
  LContent, LDecrypted: TCryptoLibByteArray;
  LChecksum: UInt32;
  LData: DeserializedData;
begin
  LMemo := AOptions.Memo;
  if (string.IsNullOrWhiteSpace(LMemo)) then
  begin
    LMemo := Memo;
  end;
  LData := Deserialize(AMessage, LMemo);
  LNonce := LData.Nonce;
  LContent := LData.Content;
  LChecksum := LData.Checksum;
  LDecrypted := TAes.Decrypt(APrivateKey, APublicKey, IntToStr(LNonce),
    LContent, UIntToStr(LChecksum));
  Result := TConverters.ConvertBytesToString(LDecrypted, TEncoding.UTF8);
end;

class function TEosCrypt.Decrypt(const APrivateKey, APublicKey,
  AMessage: string; const AOptions: DecryptionOptionalData): string;
begin
  Result := Decrypt(TEosPrivateKey.FromString(APrivateKey),
    TEosPublicKey.FromString(APublicKey), AMessage, AOptions);
end;

class function TEosCrypt.PadLeft(const AInput: string; ATotalWidth: Int32;
  APadChar: Char): String;
var
  PadCount: Int32;
begin
  PadCount := ATotalWidth - Length(AInput);
  if PadCount > 0 then
  begin
    System.SetLength(Result, ATotalWidth);
    Move(AInput[1], Result[PadCount + 1], Length(AInput) * System.SizeOf(Char));
    while PadCount > 0 do
    begin
      Result[PadCount] := APadChar;
      System.Dec(PadCount);
    end;
  end
  else
  begin
    Result := AInput;
  end;
end;

class function TEosCrypt.Serialize(const ABuff: CryptData;
  const AMemo: string): string;
var
  NonceLo, NonceHi: UInt32;
  rec: Int64Rec;
begin
  rec := Int64Rec(ABuff.Nonce);
  NonceLo := rec.Lo;
  NonceHi := rec.Hi;
  Result := AMemo;
  Result := Result + PadLeft(UIntToStr(NonceLo), 11, '.');
  Result := Result + PadLeft(UIntToStr(NonceHi), 11, '.');
  Result := Result + PadLeft(UIntToStr(ABuff.Checksum), 11, '.');
  Result := Result + TBase64.Encode(ABuff.Message);
end;

class function TEosCrypt.Deserialize(const AMessage, AMemo: string)
  : DeserializedData;
var
  Nonce: Int64;
  NonceLo, NonceHi, Checksum: UInt32;
  LMessage: string;
begin
  LMessage := StringReplace(AMessage, AMemo, '', [rfReplaceAll, rfIgnoreCase]);
  NonceLo := StrToUInt(StringReplace(System.Copy(LMessage, 1, 11), '.', '',
    [rfReplaceAll, rfIgnoreCase]));
  NonceHi := StrToUInt(StringReplace(System.Copy(LMessage, 12, 11), '.', '',
    [rfReplaceAll, rfIgnoreCase]));
  Checksum := StrToUInt(StringReplace(System.Copy(LMessage, 23, 11), '.', '',
    [rfReplaceAll, rfIgnoreCase]));
  LMessage := System.Copy(LMessage, 34);
  Int64Rec(Nonce).Lo := NonceLo;
  Int64Rec(Nonce).Hi := NonceHi;
  Result := DeserializedData.Create(Checksum, TBase64.Decode(LMessage), Nonce);
end;

{ EncryptionOptionalData }

constructor EncryptionOptionalData.Create(const AMemo: string; AMaxSize: Int32);
begin
  Memo := AMemo;
  MaxSize := AMaxSize;
end;

{ DecryptionOptionalData }

constructor DecryptionOptionalData.Create(const AMemo: string);
begin
  Memo := AMemo;
end;

end.
