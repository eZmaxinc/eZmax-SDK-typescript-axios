# ContactinformationsResponseCompound

A Contactinformations Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiContactinformationsID** | **number** | The unique ID of the Contactinformations | [default to undefined]
**fkiAddressIDDefault** | **number** | The unique ID of the Address | [optional] [default to undefined]
**fkiPhoneIDDefault** | **number** | The unique ID of the Phone. | [optional] [default to undefined]
**fkiEmailIDDefault** | **number** | The unique ID of the Email | [optional] [default to undefined]
**fkiWebsiteIDDefault** | **number** | The unique ID of the Website Default | [optional] [default to undefined]
**eContactinformationsType** | [**FieldEContactinformationsType**](FieldEContactinformationsType.md) |  | [default to undefined]
**sContactinformationsUrl** | **string** | The url of the Contactinformations | [optional] [default to undefined]
**objAddressDefault** | [**AddressResponseCompound**](AddressResponseCompound.md) |  | [optional] [default to undefined]
**objPhoneDefault** | [**PhoneResponseCompound**](PhoneResponseCompound.md) |  | [optional] [default to undefined]
**objEmailDefault** | [**EmailResponseCompound**](EmailResponseCompound.md) |  | [optional] [default to undefined]
**objWebsiteDefault** | [**WebsiteResponseCompound**](WebsiteResponseCompound.md) |  | [optional] [default to undefined]
**a_objAddress** | [**Array&lt;AddressResponseCompound&gt;**](AddressResponseCompound.md) |  | [default to undefined]
**a_objPhone** | [**Array&lt;PhoneResponseCompound&gt;**](PhoneResponseCompound.md) |  | [default to undefined]
**a_objEmail** | [**Array&lt;EmailResponseCompound&gt;**](EmailResponseCompound.md) |  | [default to undefined]
**a_objWebsite** | [**Array&lt;WebsiteResponseCompound&gt;**](WebsiteResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { ContactinformationsResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ContactinformationsResponseCompound = {
    pkiContactinformationsID,
    fkiAddressIDDefault,
    fkiPhoneIDDefault,
    fkiEmailIDDefault,
    fkiWebsiteIDDefault,
    eContactinformationsType,
    sContactinformationsUrl,
    objAddressDefault,
    objPhoneDefault,
    objEmailDefault,
    objWebsiteDefault,
    a_objAddress,
    a_objPhone,
    a_objEmail,
    a_objWebsite,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
