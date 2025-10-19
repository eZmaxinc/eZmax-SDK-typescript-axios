# ActivesessionResponse

An Activesession Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eActivesessionUsertype** | [**FieldEActivesessionUsertype**](FieldEActivesessionUsertype.md) |  | [default to undefined]
**eActivesessionOrigin** | [**FieldEActivesessionOrigin**](FieldEActivesessionOrigin.md) |  | [default to undefined]
**eActivesessionWeekdaystart** | [**FieldEActivesessionWeekdaystart**](FieldEActivesessionWeekdaystart.md) |  | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sCompanyNameX** | **string** | The Name of the Company in the language of the requester | [default to undefined]
**sDepartmentNameX** | **string** | The Name of the Department in the language of the requester | [default to undefined]
**bActivesessionDebug** | **boolean** | Whether the active session is in debug or not | [default to undefined]
**bActivesessionIssuperadmin** | **boolean** | Whether the active session is superadmin or not | [default to undefined]
**bActivesessionAttachment** | **boolean** | Can access attachment when we clone a user | [optional] [default to undefined]
**bActivesessionCanafe** | **boolean** | Can access canafe when we clone a user | [optional] [default to undefined]
**bActivesessionFinancial** | **boolean** | Can access financial element when we clone a user | [optional] [default to undefined]
**bActivesessionRealestatecompleted** | **boolean** | Can access closed realestate folders when we clone a user | [optional] [default to undefined]
**eActivesessionEzsign** | [**FieldEActivesessionEzsign**](FieldEActivesessionEzsign.md) |  | [optional] [default to undefined]
**eActivesessionEzsignaccess** | [**FieldEActivesessionEzsignaccess**](FieldEActivesessionEzsignaccess.md) |  | [default to undefined]
**eActivesessionEzsignprepaid** | [**FieldEActivesessionEzsignprepaid**](FieldEActivesessionEzsignprepaid.md) |  | [optional] [default to undefined]
**eActivesessionRealestateinprogress** | [**FieldEActivesessionRealestateinprogress**](FieldEActivesessionRealestateinprogress.md) |  | [optional] [default to undefined]
**pksCustomerCode** | **string** | The customer code assigned to your account | [default to undefined]
**fkiSystemconfigurationtypeID** | **number** | The unique ID of the Systemconfigurationtype | [default to undefined]
**fkiSignatureID** | **number** | The unique ID of the Signature | [optional] [default to undefined]

## Example

```typescript
import { ActivesessionResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ActivesessionResponse = {
    eActivesessionUsertype,
    eActivesessionOrigin,
    eActivesessionWeekdaystart,
    fkiLanguageID,
    sCompanyNameX,
    sDepartmentNameX,
    bActivesessionDebug,
    bActivesessionIssuperadmin,
    bActivesessionAttachment,
    bActivesessionCanafe,
    bActivesessionFinancial,
    bActivesessionRealestatecompleted,
    eActivesessionEzsign,
    eActivesessionEzsignaccess,
    eActivesessionEzsignprepaid,
    eActivesessionRealestateinprogress,
    pksCustomerCode,
    fkiSystemconfigurationtypeID,
    fkiSignatureID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
