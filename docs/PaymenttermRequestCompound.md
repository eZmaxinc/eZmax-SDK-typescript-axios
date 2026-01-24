# PaymenttermRequestCompound

A Paymentterm Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiPaymenttermID** | **number** | The unique ID of the Paymentterm | [optional] [default to undefined]
**sPaymenttermCode** | **string** | The code of the Paymentterm | [default to undefined]
**ePaymenttermType** | [**FieldEPaymenttermType**](FieldEPaymenttermType.md) |  | [default to undefined]
**iPaymenttermDay** | **number** | The day of the Paymentterm | [default to undefined]
**objPaymenttermDescription** | [**MultilingualPaymenttermDescription**](MultilingualPaymenttermDescription.md) |  | [default to undefined]
**bPaymenttermIsactive** | **boolean** | Whether the Paymentterm is active or not | [default to undefined]

## Example

```typescript
import { PaymenttermRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PaymenttermRequestCompound = {
    pkiPaymenttermID,
    sPaymenttermCode,
    ePaymenttermType,
    iPaymenttermDay,
    objPaymenttermDescription,
    bPaymenttermIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
