unit EosPrivateKey;

interface

uses
  SysUtils,
  RegularExpressions,
  EosPublicKey,
  KeyUtils,
  CustomAssert,
  Hasher,
  ClpArrayUtils,
  ClpIECC,
  ClpSecNamedCurves,
  ClpIX9ECParameters,
  ClpECDomainParameters,
  ClpIECDomainParameters,
  ClpECPrivateKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpECKeyPairGenerator,
  ClpBigInteger,
  ClpConverters,
  ClpBigIntegers,
  ClpEncoders,
  ClpCryptoLibTypes;

type
  IEosPrivateKey = interface(IInterface)
    ['{53EA93D7-AC0F-46A6-9E28-8DA41A24214E}']
    function IsWif(const text: string): Boolean;
    function ToBuffer(): TCryptoLibByteArray;
    function ToWif(): string;
    function ToHex(): string;
    function ToPublic(): IEosPublicKey;
    function ToString(): String;
    function GetSharedSecret(const publicKey: IEosPublicKey)
      : TCryptoLibByteArray;
  end;

type
  PrivateKeyData = record
  public
    PrivateKey: IEosPrivateKey;
    Format: string;
    KeyType: string;

    constructor Create(const APrivateKey: IEosPrivateKey;
      const AFormat, AKeyType: string);
  end;

type
  TEosPrivateKey = class sealed(TInterfacedObject, IEosPrivateKey)

  strict private
  const
    SECP256K1_CURVE = 'secp256k1';

    class var

      FCurve: IX9ECParameters;

  var
    FPrivateKey: IECPrivateKeyParameters;
    FPublicKey: IEosPublicKey;
    class constructor EosPrivateKey();
    constructor Create(const d: TBigInteger);
  private
    class function ParseKey(const PrivateKey: string): PrivateKeyData;
  public
    function IsWif(const text: string): Boolean;
    function ToBuffer(): TCryptoLibByteArray;
    function ToWif(): string;
    function ToHex(): string;
    function ToPublic(): IEosPublicKey;
    function ToString(): String; override;
    function GetSharedSecret(const publicKey: IEosPublicKey)
      : TCryptoLibByteArray;
    class function FromBuffer(const buf: TCryptoLibByteArray)
      : IEosPrivateKey; static;
    class function FromHex(const hex: string): IEosPrivateKey; static;
    class function FromBigInteger(const d: TBigInteger): IEosPrivateKey; static;
    class function FromSeed(const seed: string): IEosPrivateKey; static;
    class function FromString(const PrivateKey: string): IEosPrivateKey; static;
    class function IsValid(const AKey: string): Boolean; static;

  end;

implementation

{ TEosPrivateKey }

constructor TEosPrivateKey.Create(const d: TBigInteger);
var
  domain: IECDomainParameters;
begin
  if (not d.IsInitialized) then
  begin
    raise EArgumentException.Create('Invalid private key');
  end;
  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  FPrivateKey := TECPrivateKeyParameters.Create('ECDSA', d, domain);
end;

class constructor TEosPrivateKey.EosPrivateKey;
begin
  FCurve := TSecNamedCurves.GetByName(SECP256K1_CURVE);
end;

class function TEosPrivateKey.FromBigInteger(const d: TBigInteger)
  : IEosPrivateKey;
begin
  result := TEosPrivateKey.Create(d);
end;

class function TEosPrivateKey.FromBuffer(const buf: TCryptoLibByteArray)
  : IEosPrivateKey;
var
  buffer: TCryptoLibByteArray;
begin
  buffer := buf;
  if (buffer = nil) then
  begin
    raise EArgumentNilException.Create('Buffer Cannot be Null');
  end;

  if ((System.Length(buffer) = 33) and (buffer[32] = 1)) then
  begin
    // remove compression flag
    buffer := System.Copy(buffer, 0, 32);
  end;

  if (System.Length(buffer) <> 32) then
  begin
    raise EArgumentException.Create
      (SysUtils.Format('Expecting 32 bytes, instead got %d',
      [System.Length(buffer)]));
  end;
  result := TEosPrivateKey.Create(TBigInteger.Create(1, buffer));
end;

class function TEosPrivateKey.FromHex(const hex: string): IEosPrivateKey;
begin
  result := FromBuffer(THex.Decode(hex));
end;

class function TEosPrivateKey.FromSeed(const seed: string): IEosPrivateKey;
begin
  result := FromBuffer(THasher.SHA256(TConverters.ConvertStringToBytes(seed,
    TEncoding.UTF8)));
end;

class function TEosPrivateKey.FromString(const PrivateKey: string)
  : IEosPrivateKey;
begin
  result := ParseKey(PrivateKey).PrivateKey;
end;

class function TEosPrivateKey.ParseKey(const PrivateKey: string)
  : PrivateKeyData;
var
  RegExpr: TRegex;
  Match: TMatch;
  VersionKey: TCryptoLibByteArray;
  Version: Byte;
  LPrivateKey: IEosPrivateKey;
  KeyType, KeyString: string;
begin
  RegExpr := TRegex.Create('^PVT_([A-Za-z0-9]+)_([A-Za-z0-9]+)$');
  Match := RegExpr.Match(PrivateKey);
  if not Match.Success then
  begin
    // legacy WIF - checksum includes the version
    VersionKey := TKeyUtils.CheckDecode(PrivateKey, 'sha256x2');
    Version := VersionKey[0];
    TCustomAssert.Pass($80 = Version,
      SysUtils.Format('Expected version %x, instead got %x', [$80, Version]));
    LPrivateKey := TEosPrivateKey.FromBuffer(System.Copy(VersionKey, 1));
    result := PrivateKeyData.Create(LPrivateKey, 'WIF', 'K1');
    Exit;
  end;

  TCustomAssert.Pass(Match.Groups.Count = 3,
    'Expecting private key like: PVT_K1_base58privateKey..');
  KeyType := Match.Groups.Item[1].Value;
  KeyString := Match.Groups.Item[2].Value;
  TCustomAssert.Pass(KeyType = 'K1', 'K1 private key expected');
  LPrivateKey := TEosPrivateKey.FromBuffer(TKeyUtils.CheckDecode(KeyString,
    KeyType));
  result := PrivateKeyData.Create(LPrivateKey, 'PVT', KeyType);
end;

class function TEosPrivateKey.IsValid(const AKey: string): Boolean;
begin
  try
    result := TEosPrivateKey.FromString(AKey) <> Nil;
  except
    on E: Exception do
    begin
      result := False;
    end;
  end;
end;

function TEosPrivateKey.GetSharedSecret(const publicKey: IEosPublicKey)
  : TCryptoLibByteArray;
var
  KB, XCoordBytes, YCoordBytes, R, S: TCryptoLibByteArray;
  KBP, P: IECPoint;
begin
  KB := publicKey.ToUncompressed().ToBuffer();
  XCoordBytes := System.Copy(KB, 1, 32);
  YCoordBytes := System.Copy(KB, 33, 32);

  KBP := FCurve.Curve.CreatePoint(TBigInteger.Create(1, XCoordBytes), // x
    TBigInteger.Create(1, YCoordBytes) // y
    );
  R := ToBuffer();
  P := KBP.Multiply(TBigInteger.Create(1, R));
  S := TBigIntegers.AsUnsignedByteArray(32,
    P.Normalize.AffineXCoord.ToBigInteger);
  // SHA512 used in ECIES
  result := THasher.SHA512(S);
end;

function TEosPrivateKey.IsWif(const text: string): Boolean;
begin
  try
    result := TEosPrivateKey.ParseKey(text).Format = 'WIF';
  except
    on E: Exception do
    begin
      result := False;
    end;
  end;
end;

function TEosPrivateKey.ToBuffer: TCryptoLibByteArray;
begin
  result := TBigIntegers.AsUnsignedByteArray(32, FPrivateKey.d);
end;

function TEosPrivateKey.ToHex: string;
begin
  result := THex.Encode(ToBuffer);
end;

function TEosPrivateKey.ToPublic: IEosPublicKey;
var
  point: IECPoint;
begin
  if FPublicKey <> Nil then
  begin
    result := FPublicKey;
    Exit;
  end
  else
  begin
    point := TECKeyPairGenerator.GetCorrespondingPublicKey(FPrivateKey).Q;
    // EOS Public Keys are always Compressed.
    FPublicKey := TEosPublicKey.FromPoint
      (FCurve.Curve.DecodePoint(point.GetEncoded(True)));
    result := FPublicKey;
  end;
end;

function TEosPrivateKey.ToString: String;
begin
  result := ToWif();
end;

function TEosPrivateKey.ToWif: string;
var
  buf: TCryptoLibByteArray;
begin
  buf := ToBuffer();
  // checksum includes the version
  result := TKeyUtils.CheckEncode(TArrayUtils.Concatenate([$80], buf),
    'sha256x2');
end;

{ PrivateKeyData }

constructor PrivateKeyData.Create(const APrivateKey: IEosPrivateKey;
  const AFormat, AKeyType: string);
begin
  PrivateKey := APrivateKey;
  Format := AFormat;
  KeyType := AKeyType;
end;

end.
