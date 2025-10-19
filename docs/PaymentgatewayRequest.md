# PaymentgatewayRequest

A Paymentgateway Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiPaymentgatewayID** | **number** | The unique ID of the Paymentgateway | [optional] [default to undefined]
**ePaymentgatewayProcessor** | [**FieldEPaymentgatewayProcessor**](FieldEPaymentgatewayProcessor.md) |  | [default to undefined]
**objPaymentgatewayDescription** | [**MultilingualPaymentgatewayDescription**](MultilingualPaymentgatewayDescription.md) |  | [default to undefined]
**objCreditcardmerchant** | [**CreditcardmerchantRequestCompound**](CreditcardmerchantRequestCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { PaymentgatewayRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PaymentgatewayRequest = {
    pkiPaymentgatewayID,
    ePaymentgatewayProcessor,
    objPaymentgatewayDescription,
    objCreditcardmerchant,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
