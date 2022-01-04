unit CustomAssert;

interface

uses
  SysUtils;

type
  TCustomAssert = class sealed(TObject)

  public
    class procedure Pass(ACondition: Boolean;
      const AMessage: string = ''); static;
  end;

implementation

{ TCustomAssert }

class procedure TCustomAssert.Pass(ACondition: Boolean; const AMessage: string);
begin
  if (not ACondition) then
  begin
    raise Exception.Create(AMessage);
  end;
end;

end.
