# PaymentgatewayResponse

A Paymentgateway Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiPaymentgatewayID** | **number** | The unique ID of the Paymentgateway | [default to undefined]
**fkiCreditcardmerchantID** | **number** | The unique ID of the Creditcardmerchant | [optional] [default to undefined]
**sCreditcardmerchantDescription** | **string** | The description of the Creditcardmerchant | [optional] [default to undefined]
**ePaymentgatewayProcessor** | [**FieldEPaymentgatewayProcessor**](FieldEPaymentgatewayProcessor.md) |  | [default to undefined]
**objPaymentgatewayDescription** | [**MultilingualPaymentgatewayDescription**](MultilingualPaymentgatewayDescription.md) |  | [default to undefined]
**objCreditcardmerchant** | [**CreditcardmerchantResponseCompound**](CreditcardmerchantResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { PaymentgatewayResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PaymentgatewayResponse = {
    pkiPaymentgatewayID,
    fkiCreditcardmerchantID,
    sCreditcardmerchantDescription,
    ePaymentgatewayProcessor,
    objPaymentgatewayDescription,
    objCreditcardmerchant,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
