# ContactinformationsRequestCompound

A Contactinformations Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iAddressDefault** | **number** | The index in the a_objAddress array (zero based index) representing the Address object that should become the default one.  You can leave the value to 0 if the array is empty. | [default to undefined]
**iPhoneDefault** | **number** | The index in the a_objPhone array (zero based index) representing the Phone object that should become the default one.  You can leave the value to 0 if the array is empty. | [default to undefined]
**iEmailDefault** | **number** | The index in the a_objEmail array (zero based index) representing the Email object that should become the default one.  You can leave the value to 0 if the array is empty. | [default to undefined]
**iWebsiteDefault** | **number** | The index in the a_objWebsite array (zero based index) representing the Website object that should become the default one.  You can leave the value to 0 if the array is empty. | [default to undefined]
**a_objAddress** | [**Array&lt;AddressRequestCompound&gt;**](AddressRequestCompound.md) |  | [default to undefined]
**a_objPhone** | [**Array&lt;PhoneRequestCompound&gt;**](PhoneRequestCompound.md) |  | [default to undefined]
**a_objEmail** | [**Array&lt;EmailRequestCompound&gt;**](EmailRequestCompound.md) |  | [default to undefined]
**a_objWebsite** | [**Array&lt;WebsiteRequestCompound&gt;**](WebsiteRequestCompound.md) |  | [default to undefined]

## Example

```typescript
import { ContactinformationsRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ContactinformationsRequestCompound = {
    iAddressDefault,
    iPhoneDefault,
    iEmailDefault,
    iWebsiteDefault,
    a_objAddress,
    a_objPhone,
    a_objEmail,
    a_objWebsite,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
