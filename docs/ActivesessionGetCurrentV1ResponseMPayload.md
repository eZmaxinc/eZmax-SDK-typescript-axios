# ActivesessionGetCurrentV1ResponseMPayload

Payload for GET /1/object/activesession/getCurrent

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
**fkiEzsignuserID** | **number** | The unique ID of the Ezsignuser | [optional] [default to undefined]
**bSystemconfigurationEzsignpaidbyoffice** | **boolean** | Whether if Ezsign is paid by the company or not | [optional] [default to undefined]
**eSystemconfigurationEzsignofficeplan** | [**FieldESystemconfigurationEzsignofficeplan**](FieldESystemconfigurationEzsignofficeplan.md) |  | [optional] [default to undefined]
**eUserEzsignaccess** | [**FieldEUserEzsignaccess**](FieldEUserEzsignaccess.md) |  | [default to undefined]
**eUserEzsignprepaid** | [**FieldEUserEzsignprepaid**](FieldEUserEzsignprepaid.md) |  | [optional] [default to undefined]
**bUserEzsigntrial** | **boolean** | Whether the User\&#39;s eZsign subscription is a trial | [optional] [default to undefined]
**dtUserEzsignprepaidexpiration** | **string** | The eZsign prepaid expiration date | [optional] [default to undefined]
**dtUserNpsrequest** | **string** | The date at which the NPS questionnaire will be show | [optional] [default to undefined]
**a_pkiPermissionID** | **Array&lt;number&gt;** | An array of permissions granted to the user or api key | [default to undefined]
**objUserReal** | [**ActivesessionResponseCompoundUser**](ActivesessionResponseCompoundUser.md) |  | [default to undefined]
**objUserCloned** | [**ActivesessionResponseCompoundUser**](ActivesessionResponseCompoundUser.md) |  | [optional] [default to undefined]
**objApikey** | [**ActivesessionResponseCompoundApikey**](ActivesessionResponseCompoundApikey.md) |  | [optional] [default to undefined]
**a_eModuleInternalname** | **Array&lt;string&gt;** | An Array of Registered modules.  These are the modules that are Licensed to be used by the User or the API Key. | [default to undefined]

## Example

```typescript
import { ActivesessionGetCurrentV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ActivesessionGetCurrentV1ResponseMPayload = {
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
    fkiEzsignuserID,
    bSystemconfigurationEzsignpaidbyoffice,
    eSystemconfigurationEzsignofficeplan,
    eUserEzsignaccess,
    eUserEzsignprepaid,
    bUserEzsigntrial,
    dtUserEzsignprepaidexpiration,
    dtUserNpsrequest,
    a_pkiPermissionID,
    objUserReal,
    objUserCloned,
    objApikey,
    a_eModuleInternalname,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
