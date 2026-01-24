# PhoneRequestCompound

A Phone Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiPhoneID** | **number** | The unique ID of the Phone. | [optional] [default to undefined]
**fkiPhonetypeID** | **number** | The unique ID of the Phonetype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| |3|Mobile| |4|Fax| |5|Pager| |6|Toll Free| | [default to undefined]
**ePhoneType** | [**FieldEPhoneType**](FieldEPhoneType.md) |  | [optional] [default to undefined]
**sPhoneRegion** | **string** | The region of the phone number. (For a North America Number only)  The region is the \&quot;514\&quot; section in this sample phone number: (514) 990-1516 x123 | [optional] [default to undefined]
**sPhoneExchange** | **string** | The exchange of the phone number. (For a North America Number only)  The exchange is the \&quot;990\&quot; section in this sample phone number: (514) 990-1516 x123 | [optional] [default to undefined]
**sPhoneNumber** | **string** | The number of the phone number. (For a North America Number only)  The number is the \&quot;1516\&quot; section in this sample phone number: (514) 990-1516 x123 | [optional] [default to undefined]
**sPhoneInternational** | **string** | The international phone number. | [optional] [default to undefined]
**sPhoneExtension** | **string** | The extension of the phone number.  The extension is the \&quot;123\&quot; section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers | [optional] [default to undefined]
**sPhoneE164** | **string** | A phone number in E.164 Format | [optional] [default to undefined]

## Example

```typescript
import { PhoneRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PhoneRequestCompound = {
    pkiPhoneID,
    fkiPhonetypeID,
    ePhoneType,
    sPhoneRegion,
    sPhoneExchange,
    sPhoneNumber,
    sPhoneInternational,
    sPhoneExtension,
    sPhoneE164,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
