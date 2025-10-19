# CustomerListElement

A Customer List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCustomerID** | **number** | The unique ID of the Customer. | [default to undefined]
**sCustomerName** | **string** | The name of the Customer | [default to undefined]
**sCustomerNote** | **string** | A note for the Customer | [optional] [default to undefined]
**sCustomerCode** | **string** | The code of the Customer | [default to undefined]
**bCustomerIsactive** | **boolean** | Whether the customer is active or not | [default to undefined]
**sPhoneE164** | **string** | A phone number in E.164 Format | [optional] [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**sAddressCivic** | **string** | The Civic number. | [optional] [default to undefined]
**sAddressStreet** | **string** | The Street Name | [optional] [default to undefined]
**sAddressSuite** | **string** | The Suite or appartment number | [optional] [default to undefined]
**sAddressCity** | **string** | The City name | [optional] [default to undefined]
**sAddressZip** | **string** | The Postal/Zip Code  The value must be entered without spaces | [optional] [default to undefined]
**sProvinceNameX** | **string** | The name of the Province in the language of the requester | [optional] [default to undefined]
**sCountryNameX** | **string** | The name of the Country in the language of the requester | [optional] [default to undefined]

## Example

```typescript
import { CustomerListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomerListElement = {
    pkiCustomerID,
    sCustomerName,
    sCustomerNote,
    sCustomerCode,
    bCustomerIsactive,
    sPhoneE164,
    sEmailAddress,
    sAddressCivic,
    sAddressStreet,
    sAddressSuite,
    sAddressCity,
    sAddressZip,
    sProvinceNameX,
    sCountryNameX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
