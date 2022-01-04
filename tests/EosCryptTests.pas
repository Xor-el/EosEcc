unit EosCryptTests;

interface

uses
  SysUtils,
  RegularExpressions,
  EosCrypt,
  ClpConverters,
  TestFramework;

type

  TTestEosCrypt = class(TTestCase)
  private

    const
    &Message = 'Private Message, shhhh!';
    PublicKey = 'EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV';
    PrivateKey = '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3';
    EncryptedMessage = 'TO DECRYPT: eos-encrypt' + AnsiChar(#10) +
      '.1606600682...23465070.2645171489fuTcDTGHDazPpNifTEM74kOziWL7CFMTMAy4SoTuYEs=';
    LongMessage = 'Very long message XXXXXXXXXXXXXXXXXXXXXX' + AnsiChar(#10) +
      'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
      + AnsiChar(#10) +
      'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
      + AnsiChar(#10) +
      'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';

    TestEncryptionOptionalData: EncryptionOptionalData = (Memo: ''; MaxSize: 0);

    TestDecryptionOptionalData: DecryptionOptionalData = (Memo: '');

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure Test_Encrypt;
    procedure Test_Decrypt;
    procedure Test_Encrypt_Decrypt;
    procedure Test_Encrypt_Does_Not_Throw_For_Unlimited_Max_Size;
    procedure Test_Encrypt_Does_Throw_When_Message_Length_Exceeds_Defined_Max_Size;
    procedure Test_Encrypt_Does_Throw_When_Message_Length_Exceeds_Default_Max_Size;
    procedure Test_Encrypt_With_Custom_Memo_Works;

  end;

implementation

procedure TTestEosCrypt.SetUp;
begin
  inherited;

end;

procedure TTestEosCrypt.TearDown;
begin
  inherited;

end;

procedure TTestEosCrypt.Test_Encrypt;
var
  Encrypted: string;
  Data: DeserializedData;
begin
  try
    Encrypted := TEosCrypt.Encrypt(PrivateKey, PublicKey,
      TConverters.ConvertStringToBytes(&Message, TEncoding.UTF8),
      TestEncryptionOptionalData);
    Data := TEosCrypt.Deserialize(Encrypted);
  except
    on e: Exception do
    begin
      Fail('encryption failed');
    end;
  end;
end;

procedure TTestEosCrypt.Test_Decrypt;
var
  Decrypted: string;
begin
  try
    Decrypted := TEosCrypt.Decrypt(PrivateKey, PublicKey, EncryptedMessage,
      TestDecryptionOptionalData);
  except
    on e: Exception do
    begin
      Fail('decryption failed');
    end;
  end;
  CheckEquals(&Message, Decrypted);
end;

procedure TTestEosCrypt.Test_Encrypt_Decrypt;
var
  Encrypted, Decrypted: string;
begin
  try
    Encrypted := TEosCrypt.Encrypt(PrivateKey, PublicKey,
      TConverters.ConvertStringToBytes(&Message, TEncoding.UTF8),
      TestEncryptionOptionalData);
    Decrypted := TEosCrypt.Decrypt(PrivateKey, PublicKey, Encrypted,
      TestDecryptionOptionalData);
  except
    on e: Exception do
    begin
      Fail('encryption/decryption failed');
    end;
  end;
  CheckEquals(&Message, Decrypted);
end;

procedure TTestEosCrypt.Test_Encrypt_Does_Not_Throw_For_Unlimited_Max_Size;
var
  Encrypted: string;
begin
  try
    Encrypted := TEosCrypt.Encrypt(PrivateKey, PublicKey,
      TConverters.ConvertStringToBytes(LongMessage, TEncoding.UTF8),
      EncryptionOptionalData.Create('', -1));
  except
    on e: Exception do
    begin
      Fail('unlimited max size should not throw');
    end;
  end;
end;

procedure TTestEosCrypt.
  Test_Encrypt_Does_Throw_When_Message_Length_Exceeds_Default_Max_Size;
var
  Encrypted, ErrorMessage: string;
begin
  try
    Encrypted := TEosCrypt.Encrypt(PrivateKey, PublicKey,
      TConverters.ConvertStringToBytes(LongMessage, TEncoding.UTF8),
      TestEncryptionOptionalData);
    Fail('should throw when message length exceeds default maxsize');
  except
    on e: Exception do
    begin
      ErrorMessage := e.Message;
    end;
  end;
  CheckEquals('message too long (max 256 chars)', ErrorMessage);
end;

procedure TTestEosCrypt.
  Test_Encrypt_Does_Throw_When_Message_Length_Exceeds_Defined_Max_Size;
var
  Encrypted, ErrorMessage: string;
begin
  try
    Encrypted := TEosCrypt.Encrypt(PrivateKey, PublicKey,
      TConverters.ConvertStringToBytes(LongMessage, TEncoding.UTF8),
      EncryptionOptionalData.Create('', 5));
    Fail('should throw when message length exceeds defined maxsize');
  except
    on e: Exception do
    begin
      ErrorMessage := e.Message;
    end;
  end;
  CheckEquals('message too long (max 5 chars)', ErrorMessage);
end;

procedure TTestEosCrypt.Test_Encrypt_With_Custom_Memo_Works;
var
  Encrypted: string;
  RegExpr: TRegex;
  Match: TMatch;
begin
  try
    Encrypted := TEosCrypt.Encrypt(PrivateKey, PublicKey,
      TConverters.ConvertStringToBytes(&Message, TEncoding.UTF8),
      EncryptionOptionalData.Create('Dorime', 0));
    RegExpr := TRegex.Create('Dorime');
    Match := RegExpr.Match(Encrypted);
  except
    on e: Exception do
    begin
      Fail('encrypt with custom memo failed');
    end;
  end;
  CheckTrue(Match.Success);
end;

initialization

// Register any test cases with the test runner

RegisterTest(TTestEosCrypt.Suite);

end.
