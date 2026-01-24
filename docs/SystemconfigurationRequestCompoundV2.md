# SystemconfigurationRequestCompoundV2

A Systemconfiguration Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSystemconfigurationID** | **number** | The unique ID of the Systemconfiguration | [optional] [default to undefined]
**fkiBrandingID** | **number** | The unique ID of the Branding | [optional] [default to undefined]
**eSystemconfigurationNewexternaluseraction** | [**FieldESystemconfigurationNewexternaluseraction**](FieldESystemconfigurationNewexternaluseraction.md) |  | [default to undefined]
**eSystemconfigurationLanguage1** | [**FieldESystemconfigurationLanguage1**](FieldESystemconfigurationLanguage1.md) |  | [default to undefined]
**eSystemconfigurationLanguage2** | [**FieldESystemconfigurationLanguage2**](FieldESystemconfigurationLanguage2.md) |  | [default to undefined]
**eSystemconfigurationEzsignofficeplan** | [**FieldESystemconfigurationEzsignofficeplan**](FieldESystemconfigurationEzsignofficeplan.md) |  | [optional] [default to undefined]
**bSystemconfigurationEzsignpaidbyoffice** | **boolean** | Whether if Ezsign is paid by the company or not | [optional] [default to undefined]
**bSystemconfigurationEzsignpersonnal** | **boolean** | Whether if we allow the creation of personal files in eZsign | [default to undefined]
**bSystemconfigurationSspr** | **boolean** | Whether if we allow SSPR | [default to undefined]
**dtSystemconfigurationReadonlyexpirationstart** | **string** | The start date where the system will be in read only | [optional] [default to undefined]
**dtSystemconfigurationReadonlyexpirationend** | **string** | The end date where the system will be in read only | [optional] [default to undefined]
**iSystemconfigurationEzsignreminderhoursend** | **number** | The hour we will send the eZsign reminders | [default to undefined]

## Example

```typescript
import { SystemconfigurationRequestCompoundV2 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SystemconfigurationRequestCompoundV2 = {
    pkiSystemconfigurationID,
    fkiBrandingID,
    eSystemconfigurationNewexternaluseraction,
    eSystemconfigurationLanguage1,
    eSystemconfigurationLanguage2,
    eSystemconfigurationEzsignofficeplan,
    bSystemconfigurationEzsignpaidbyoffice,
    bSystemconfigurationEzsignpersonnal,
    bSystemconfigurationSspr,
    dtSystemconfigurationReadonlyexpirationstart,
    dtSystemconfigurationReadonlyexpirationend,
    iSystemconfigurationEzsignreminderhoursend,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
