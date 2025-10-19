# CustomCreditcardtransactionResponse

A custom Creditcardtransaction Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eCreditcardtypeCodename** | [**FieldECreditcardtypeCodename**](FieldECreditcardtypeCodename.md) |  | [default to undefined]
**dCreditcardtransactionAmount** | **string** | The amount of the Creditcardtransaction | [default to undefined]
**sCreditcardtransactionPartiallydecryptednumber** | **string** | The partially decrypted credit card number used in the Creditcardtransaction | [default to undefined]
**sCreditcardtransactionReferencenumber** | **string** | The reference number on the creditcard service for the Creditcardtransaction | [default to undefined]

## Example

```typescript
import { CustomCreditcardtransactionResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomCreditcardtransactionResponse = {
    eCreditcardtypeCodename,
    dCreditcardtransactionAmount,
    sCreditcardtransactionPartiallydecryptednumber,
    sCreditcardtransactionReferencenumber,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
