# PaymentgatewayListElement

A Paymentgateway List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiPaymentgatewayID** | **number** | The unique ID of the Paymentgateway | [default to undefined]
**fkiCreditcardmerchantID** | **number** | The unique ID of the Creditcardmerchant | [default to undefined]
**ePaymentgatewayProcessor** | [**FieldEPaymentgatewayProcessor**](FieldEPaymentgatewayProcessor.md) |  | [default to undefined]
**sPaymentgatewayDescriptionX** | **string** | The description of the Paymentgateway in the language of the requester | [default to undefined]
**bPaymentgatewayIsactive** | **boolean** | Whether the Paymentgateway is active or not | [default to undefined]

## Example

```typescript
import { PaymentgatewayListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PaymentgatewayListElement = {
    pkiPaymentgatewayID,
    fkiCreditcardmerchantID,
    ePaymentgatewayProcessor,
    sPaymentgatewayDescriptionX,
    bPaymentgatewayIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
