# SystemconfigurationResponse

A Systemconfiguration Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSystemconfigurationID** | **number** | The unique ID of the Systemconfiguration | [default to undefined]
**fkiSystemconfigurationtypeID** | **number** | The unique ID of the Systemconfigurationtype | [default to undefined]
**fkiBrandingID** | **number** | The unique ID of the Branding | [optional] [default to undefined]
**sSystemconfigurationtypeDescriptionX** | **string** | The description of the Systemconfigurationtype in the language of the requester | [default to undefined]
**eSystemconfigurationNewexternaluseraction** | [**FieldESystemconfigurationNewexternaluseraction**](FieldESystemconfigurationNewexternaluseraction.md) |  | [default to undefined]
**eSystemconfigurationLanguage1** | [**FieldESystemconfigurationLanguage1**](FieldESystemconfigurationLanguage1.md) |  | [default to undefined]
**eSystemconfigurationLanguage2** | [**FieldESystemconfigurationLanguage2**](FieldESystemconfigurationLanguage2.md) |  | [default to undefined]
**eSystemconfigurationEzsign** | [**FieldESystemconfigurationEzsign**](FieldESystemconfigurationEzsign.md) |  | [optional] [default to undefined]
**eSystemconfigurationEzsignofficeplan** | [**FieldESystemconfigurationEzsignofficeplan**](FieldESystemconfigurationEzsignofficeplan.md) |  | [optional] [default to undefined]
**bSystemconfigurationEzsignpaidbyoffice** | **boolean** | Whether if Ezsign is paid by the company or not | [optional] [default to undefined]
**bSystemconfigurationEzsignpersonnal** | **boolean** | Whether if we allow the creation of personal files in eZsign | [default to undefined]
**bSystemconfigurationHascreditcardmerchant** | **boolean** | Whether there is a creditcard merchant configured or not | [optional] [default to undefined]
**bSystemconfigurationIsdisposalactive** | **boolean** | Whether is Disposal processus is active or not | [optional] [default to undefined]
**bSystemconfigurationSspr** | **boolean** | Whether if we allow SSPR | [default to undefined]
**dtSystemconfigurationReadonlyexpirationstart** | **string** | The start date where the system will be in read only | [optional] [default to undefined]
**dtSystemconfigurationReadonlyexpirationend** | **string** | The end date where the system will be in read only | [optional] [default to undefined]
**objBranding** | [**CustomBrandingResponse**](CustomBrandingResponse.md) |  | [optional] [default to undefined]

## Example

```typescript
import { SystemconfigurationResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SystemconfigurationResponse = {
    pkiSystemconfigurationID,
    fkiSystemconfigurationtypeID,
    fkiBrandingID,
    sSystemconfigurationtypeDescriptionX,
    eSystemconfigurationNewexternaluseraction,
    eSystemconfigurationLanguage1,
    eSystemconfigurationLanguage2,
    eSystemconfigurationEzsign,
    eSystemconfigurationEzsignofficeplan,
    bSystemconfigurationEzsignpaidbyoffice,
    bSystemconfigurationEzsignpersonnal,
    bSystemconfigurationHascreditcardmerchant,
    bSystemconfigurationIsdisposalactive,
    bSystemconfigurationSspr,
    dtSystemconfigurationReadonlyexpirationstart,
    dtSystemconfigurationReadonlyexpirationend,
    objBranding,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
