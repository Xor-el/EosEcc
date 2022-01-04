unit EosKeyTests;

interface

uses
  SysUtils,
  EosPrivateKey,
  EosPublicKey,
  Hasher,
  TestFramework;

type

  TTestEosKey = class(TTestCase)
  private

    const
    PvtError = 'key comparison test failed on a known private key';
    PubError = 'pubkey string comparison test failed on a known public key';

  var
    FPvt: IEosPrivateKey;
    FPub: IEosPublicKey;
    procedure CallWifToEosPrivateKey();
    procedure CallPvtToEosPrivateKey();
    procedure CallPublicKeyToEosPublicKey();
    function IsValidPublic(const pubKey: string;
      const prefix: string = 'EOS'): Boolean;
    function IsValidPrivate(const privKey: string): Boolean;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure Test_Wif_To_EosPrivateKey_Does_Not_Throw;
    procedure Test_Pvt_To_EosPrivateKey_Does_Not_Throw;
    procedure Test_Public_Key_To_EosPublicKey_Does_Not_Throw;
    procedure Test_EosPrivateKey_To_Wif;
    procedure Test_EosPrivateKey_From_Seed_To_Wif;
    procedure Test_EosPublicKey_To_String;
    procedure Test_EosPrivateKey_Wif_To_PublicKeyString;
    procedure Test_EosPrivateKey_From_TestNet_One_To_PublicKeyString;
    procedure Test_EosPrivateKey_From_TestNet_Two_To_PublicKeyString;
    procedure Test_EosPrivateKey_From_TestNet_Three_To_PublicKeyString;
    procedure Test_EosPublicKey_Is_Valid_One;
    procedure Test_EosPublicKey_Is_Valid_Two;
    procedure Test_EosPublicKey_Is_Valid_Three;
    procedure Test_EosPublicKey_Is_Invalid_One;
    procedure Test_EosPublicKey_Is_Invalid_Two;
    procedure Test_EosPublicKey_Is_Invalid_Three;
    procedure Test_EosPrivateKey_Is_Valid;
    procedure Test_EosPrivateKey_Is_Invalid;

  end;

implementation

procedure TTestEosKey.CallPublicKeyToEosPublicKey;
begin
  TEosPublicKey.FromString(FPub.ToString());
end;

procedure TTestEosKey.CallPvtToEosPrivateKey;
begin
  TEosPrivateKey.FromString(FPvt.ToString());
end;

procedure TTestEosKey.CallWifToEosPrivateKey;
begin
  TEosPrivateKey.FromString(FPvt.toWif());
end;

function TTestEosKey.IsValidPublic(const pubKey, prefix: string): Boolean;
begin
  Result := TEosPublicKey.IsValid(pubKey, prefix);
end;

function TTestEosKey.IsValidPrivate(const privKey: string): Boolean;
begin
  Result := TEosPrivateKey.IsValid(privKey);
end;

procedure TTestEosKey.SetUp;
begin
  inherited;
  FPvt := TEosPrivateKey.FromBuffer(THasher.SHA256([]));
  FPub := FPvt.ToPublic();
end;

procedure TTestEosKey.TearDown;
begin
  inherited;

end;

procedure TTestEosKey.Test_EosPrivateKey_Wif_To_PublicKeyString;
var
  privKey: IEosPrivateKey;
begin
  privKey := TEosPrivateKey.FromString
    ('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss');
  CheckEquals('EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM',
    privKey.ToPublic.ToString(), PubError);
end;

procedure TTestEosKey.Test_EosPrivateKey_From_Seed_To_Wif;
var
  privKey: IEosPrivateKey;
begin
  privKey := TEosPrivateKey.FromSeed('');
  CheckEquals('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss',
    privKey.toWif(), PvtError);
end;

procedure TTestEosKey.Test_EosPrivateKey_From_TestNet_One_To_PublicKeyString;
var
  privKey: IEosPrivateKey;
begin
  privKey := TEosPrivateKey.FromString
    ('5KLdk8uKJjEKjWpAFqmr37s5V735ESJpaEjyNYkFRZkSJg9Xgxn');
  CheckEquals('EOS8D5KCyLFXxkcdG7Y2AcmCbpo1NgVNBkwjnZm9jdSwoGGgqCP7W',
    privKey.ToPublic.ToString(), PubError);
end;

procedure TTestEosKey.Test_EosPrivateKey_From_TestNet_Two_To_PublicKeyString;
var
  privKey: IEosPrivateKey;
begin
  privKey := TEosPrivateKey.FromString
    ('5JxmfaGxBJ2fkyy6VSPbtKSMty54xspxzdoxh1D3CrpeR5XSoQk');
  CheckEquals('EOS5ZrFQeqh1XheJkQAVK7QQnraNS5JnffJFnHPkCNM3WTTM9fm9g',
    privKey.ToPublic.ToString(), PubError);
end;

procedure TTestEosKey.Test_EosPrivateKey_From_TestNet_Three_To_PublicKeyString;
var
  privKey: IEosPrivateKey;
begin
  privKey := TEosPrivateKey.FromString
    ('5K4G22PKBRqUqjRufVEbLwoKnVaucATKqxzsEFq6PiMnhrQH7xG');
  CheckEquals('EOS7r5of2Yb1x7MvxrE37AbWhuXyQqgVAN1ppsigGkG7hednGkBHw',
    privKey.ToPublic.ToString(), PubError);
end;

procedure TTestEosKey.Test_EosPrivateKey_To_Wif;
begin
  CheckEquals('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss', FPvt.toWif,
    PvtError);
end;

procedure TTestEosKey.Test_EosPublicKey_To_String;
begin
  CheckEquals('EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM',
    FPub.ToString, PubError);
end;

procedure TTestEosKey.Test_Public_Key_To_EosPublicKey_Does_Not_Throw;
begin
  try
    CallPublicKeyToEosPublicKey;
  except
    on e: Exception do
    begin
      Fail('converting known public key from string');
    end;
  end;
end;

procedure TTestEosKey.Test_Pvt_To_EosPrivateKey_Does_Not_Throw;
begin
  try
    CallPvtToEosPrivateKey;
  except
    on e: Exception do
    begin
      Fail('converting known pvt from string');
    end;
  end;
end;

procedure TTestEosKey.Test_Wif_To_EosPrivateKey_Does_Not_Throw;
begin
  try
    CallWifToEosPrivateKey;
  except
    on e: Exception do
    begin
      Fail('converting known wif from string');
    end;
  end;
end;

procedure TTestEosKey.Test_EosPublicKey_Is_Valid_One;
begin
  CheckTrue(IsValidPublic
    ('PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX'));
end;

procedure TTestEosKey.Test_EosPublicKey_Is_Valid_Two;
begin
  CheckTrue(IsValidPublic
    ('EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM'));
end;

procedure TTestEosKey.Test_EosPublicKey_Is_Valid_Three;
begin
  CheckTrue(IsValidPublic
    ('PUB859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', 'PUB'));
end;

procedure TTestEosKey.Test_EosPublicKey_Is_Invalid_One;
begin
  CheckFalse(IsValidPublic
    ('MMM859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM'));
end;

procedure TTestEosKey.Test_EosPublicKey_Is_Invalid_Two;
begin
  CheckFalse(IsValidPublic
    ('EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVm', 'EOS'));
end;

procedure TTestEosKey.Test_EosPublicKey_Is_Invalid_Three;
begin
  CheckFalse(IsValidPublic
    ('PUB859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVm', 'PUB'));
end;

procedure TTestEosKey.Test_EosPrivateKey_Is_Valid;
begin
  CheckTrue(IsValidPrivate
    ('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'));
end;

procedure TTestEosKey.Test_EosPrivateKey_Is_Invalid;
begin
  CheckFalse(IsValidPrivate
    ('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjsm'));
end;

initialization

// Register any test cases with the test runner

RegisterTest(TTestEosKey.Suite);

end.
