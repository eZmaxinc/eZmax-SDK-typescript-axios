# PaymenttermListElement

A Paymentterm List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiPaymenttermID** | **number** | The unique ID of the Paymentterm | [default to undefined]
**sPaymenttermCode** | **string** | The code of the Paymentterm | [default to undefined]
**ePaymenttermType** | [**FieldEPaymenttermType**](FieldEPaymenttermType.md) |  | [default to undefined]
**iPaymenttermDay** | **number** | The day of the Paymentterm | [default to undefined]
**sPaymenttermDescriptionX** | **string** | The description of the Paymentterm in the language of the requester | [default to undefined]
**bPaymenttermIsactive** | **boolean** | Whether the Paymentterm is active or not | [default to undefined]

## Example

```typescript
import { PaymenttermListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PaymenttermListElement = {
    pkiPaymenttermID,
    sPaymenttermCode,
    ePaymenttermType,
    iPaymenttermDay,
    sPaymenttermDescriptionX,
    bPaymenttermIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
