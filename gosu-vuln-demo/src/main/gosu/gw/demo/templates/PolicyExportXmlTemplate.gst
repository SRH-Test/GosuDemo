<%@ params(accountNumber : String, insuredName : String, rawXmlExtension : String, apiSecret : String) %>
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Intentionally vulnerable Gosu XML Template (.gst).
  Interpolates unescaped user strings into an ACORD XML payload (CWE-91 XML Injection)
  and embeds sensitive API credentials in exported XML (CWE-200 / CWE-532).
-->
<ACORD>
  <SignonRq>
    <SignonPswd>
      <CustId>
        <CustLoginId>${accountNumber}</CustLoginId>
      </CustId>
      <Pswd>${apiSecret}</Pswd>
    </SignonPswd>
  </SignonRq>
  <InsuranceSvcRq>
    <ClaimsNotificationAddRq>
      <InsuredOrPrincipal>
        <GeneralPartyInfo>
          <NameInfo>
            <CommlName>${insuredName}</CommlName>
          </NameInfo>
        </GeneralPartyInfo>
      </InsuredOrPrincipal>
      <CustomExtension>${rawXmlExtension}</CustomExtension>
    </ClaimsNotificationAddRq>
  </InsuranceSvcRq>
</ACORD>
