# PhoneRequestV2

A Phone Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiPhoneID** | **number** | The unique ID of the Phone. | [optional] [default to undefined]
**fkiPhonetypeID** | **number** | The unique ID of the Phonetype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| |3|Mobile| |4|Fax| |5|Pager| |6|Toll Free| | [default to undefined]
**sPhoneExtension** | **string** | The extension of the phone number.  The extension is the \&quot;123\&quot; section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers | [optional] [default to undefined]
**sPhoneE164** | **string** | A phone number in E.164 Format | [optional] [default to undefined]

## Example

```typescript
import { PhoneRequestV2 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PhoneRequestV2 = {
    pkiPhoneID,
    fkiPhonetypeID,
    sPhoneExtension,
    sPhoneE164,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
