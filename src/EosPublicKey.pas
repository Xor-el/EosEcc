unit EosPublicKey;

interface

uses
  SysUtils,
  RegularExpressions,
  KeyUtils,
  CustomAssert,
  ClpSecNamedCurves,
  ClpIX9ECParameters,
  ClpIECC,
  ClpECDomainParameters,
  ClpIECDomainParameters,
  ClpECPublicKeyParameters,
  ClpIECPublicKeyParameters,
  ClpEncoders,
  ClpCryptoLibTypes;

type
  IEosPublicKey = interface(IInterface)
    ['{87C68ECE-CC6B-4E98-AD03-1A4624CBF5E7}']
    function ToBuffer(): TCryptoLibByteArray;
    function ToUncompressed(): IEosPublicKey;
    function ToHex(): string;
    function ToString(const APubKeyPrefix: string = 'EOS'): String;
  end;

type
  TEosPublicKey = class sealed(TInterfacedObject, IEosPublicKey)

  strict private
  const
    SECP256K1_CURVE = 'secp256k1';

    class var

      FCurve: IX9ECParameters;

  var
    FPublicKey: IECPublicKeyParameters;
    class constructor EosPublicKey();
    constructor Create(const q: IECPoint);
    class function FromStringOrThrow(const APublicKey: string;
      const APubKeyPrefix: string): IEosPublicKey;
  public
    function ToBuffer(): TCryptoLibByteArray;
    function ToUncompressed(): IEosPublicKey;
    function ToHex(): string;
    function ToString(const APubKeyPrefix: string = 'EOS'): String;
    class function FromBuffer(const buf: TCryptoLibByteArray)
      : IEosPublicKey; static;
    class function FromHex(const hex: string): IEosPublicKey; static;
    class function FromString(const APublicKey: string;
      const APubKeyPrefix: string = 'EOS'): IEosPublicKey; static;
    class function FromPoint(const q: IECPoint): IEosPublicKey; static;
    class function IsValid(const AKey: string;
      const APubKeyPrefix: string = 'EOS'): Boolean; static;

  end;

implementation

{ TEosPublicKey }

constructor TEosPublicKey.Create(const q: IECPoint);
var
  domain: IECDomainParameters;
begin
  if (q = nil) then
  begin
    raise EArgumentNilException.Create('Point cannot be Null');
  end;
  if ((not q.IsValid)) then
  begin
    raise EArgumentException.Create('Invalid public key');
  end;
  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  FPublicKey := TECPublicKeyParameters.Create(q, domain);
end;

class constructor TEosPublicKey.EosPublicKey;
begin
  FCurve := TSecNamedCurves.GetByName(SECP256K1_CURVE);
end;

class function TEosPublicKey.FromBuffer(const buf: TCryptoLibByteArray)
  : IEosPublicKey;
begin
  Result := FromPoint(FCurve.Curve.DecodePoint(buf));
end;

class function TEosPublicKey.FromHex(const hex: string): IEosPublicKey;
begin
  Result := FromBuffer(THex.Decode(hex));
end;

class function TEosPublicKey.FromPoint(const q: IECPoint): IEosPublicKey;
begin
  Result := TEosPublicKey.Create(q);
end;

class function TEosPublicKey.FromString(const APublicKey: string;
  const APubKeyPrefix: string): IEosPublicKey;
begin
  try
    Result := TEosPublicKey.FromStringOrThrow(APublicKey, APubKeyPrefix);
  except
    on E: Exception do
    begin
      Result := Nil;
    end;
  end;
end;

class function TEosPublicKey.FromStringOrThrow(const APublicKey: string;
  const APubKeyPrefix: string): IEosPublicKey;
var
  RegExpr, PrefixMatch: TRegex;
  Match: TMatch;
  LPublicKey, KeyType, KeyString: string;
begin
  LPublicKey := APublicKey;
  RegExpr := TRegex.Create('^PUB_([A-Za-z0-9]+)_([A-Za-z0-9]+)$');
  Match := RegExpr.Match(LPublicKey);
  if not Match.Success then
  begin
    // legacy
    PrefixMatch := TRegex.Create('^' + APubKeyPrefix);
    Match := PrefixMatch.Match(LPublicKey);
    if (Match.Success) then
    begin
      LPublicKey := System.Copy(LPublicKey, System.Length(APubKeyPrefix) + 1);
    end;
    Result := TEosPublicKey.FromBuffer(TKeyUtils.CheckDecode(LPublicKey));
    Exit;
  end;

  TCustomAssert.Pass(Match.Groups.Count = 3,
    'Expecting public key like: PUB_K1_base58pubkey..');
  KeyType := Match.Groups.Item[1].Value;
  KeyString := Match.Groups.Item[2].Value;
  TCustomAssert.Pass(KeyType = 'K1', 'K1 private key expected');
  Result := TEosPublicKey.FromBuffer(TKeyUtils.CheckDecode(KeyString, KeyType));
end;

class function TEosPublicKey.IsValid(const AKey: string;
  const APubKeyPrefix: string): Boolean;
begin
  try
    Result := TEosPublicKey.FromString(AKey, APubKeyPrefix) <> Nil;
  except
    on E: Exception do
    begin
      Result := False;
    end;
  end;
end;

function TEosPublicKey.ToBuffer: TCryptoLibByteArray;
var
  point: IECPoint;
begin
  point := FPublicKey.q;
  Result := point.GetEncoded(point.IsCompressed);
end;

function TEosPublicKey.ToUncompressed: IEosPublicKey;
var
  buf: TCryptoLibByteArray;
begin
  buf := FPublicKey.q.GetEncoded(False);
  Result := FromPoint(FCurve.Curve.DecodePoint(buf));
end;

function TEosPublicKey.ToHex: string;
begin
  Result := THex.Encode(ToBuffer);
end;

function TEosPublicKey.ToString(const APubKeyPrefix: string): String;
begin
  Result := APubKeyPrefix + TKeyUtils.CheckEncode(ToBuffer());
end;

end.
