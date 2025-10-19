# CreditcardclientRequest

A Creditcardclient Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCreditcardclientID** | **number** | The unique ID of the Creditcardclient | [optional] [default to undefined]
**fksCreditcardtokenID** | **string** | The creditcard token identifier | [optional] [default to undefined]
**bCreditcardclientrelationIsdefault** | **boolean** | Whether if it\&#39;s the creditcardclient is the default one | [default to undefined]
**sCreditcardclientDescription** | **string** | The description of the Creditcardclient | [default to undefined]
**bCreditcardclientAllowedcompanypayment** | **boolean** | Whether if it\&#39;s an allowedagencypayment | [default to undefined]
**bCreditcardclientAllowedezsign** | **boolean** | Whether if it\&#39;s an allowedroyallepageprotection | [default to undefined]
**bCreditcardclientAllowedtranquillit** | **boolean** | Whether if it\&#39;s an allowedtranquillit | [default to undefined]
**objCreditcarddetail** | [**CreditcarddetailRequest**](CreditcarddetailRequest.md) |  | [default to undefined]
**sCreditcardclientCVV** | **string** | The creditcard card CVV | [default to undefined]

## Example

```typescript
import { CreditcardclientRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CreditcardclientRequest = {
    pkiCreditcardclientID,
    fksCreditcardtokenID,
    bCreditcardclientrelationIsdefault,
    sCreditcardclientDescription,
    bCreditcardclientAllowedcompanypayment,
    bCreditcardclientAllowedezsign,
    bCreditcardclientAllowedtranquillit,
    objCreditcarddetail,
    sCreditcardclientCVV,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
