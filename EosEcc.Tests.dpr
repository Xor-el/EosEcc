program EosEcc.Tests;
{

  Delphi DUnit Test Project
  -------------------------
  This project contains the DUnit test framework and the GUI/Console test runners.
  Add "CONSOLE_TESTRUNNER" to the conditional defines entry in the project options
  to use the console test runner.  Otherwise the GUI test runner will be used by
  default.

}

{$WARN DUPLICATE_CTOR_DTOR OFF}
{$IFDEF CONSOLE_TESTRUNNER}
{$APPTYPE CONSOLE}
{$ENDIF}

uses
  Forms,
  TestFramework,
  GUITestRunner,
  TextTestRunner,
  CustomAssert in 'src\CustomAssert.pas',
  EosPrivateKey in 'src\EosPrivateKey.pas',
  EosPublicKey in 'src\EosPublicKey.pas',
  Hasher in 'src\Hasher.pas',
  KeyUtils in 'src\KeyUtils.pas',
  EosKeyTests in 'tests\EosKeyTests.pas',
  Aes in 'src\Aes.pas',
  EosCrypt in 'src\EosCrypt.pas',
  EosCryptTests in 'tests\EosCryptTests.pas';

begin
  Application.Initialize;
  if IsConsole then
    TextTestRunner.RunRegisteredTests
  else
    GUITestRunner.RunRegisteredTests;

end.
