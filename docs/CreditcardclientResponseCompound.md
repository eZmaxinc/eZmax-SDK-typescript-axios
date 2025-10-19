# CreditcardclientResponseCompound

A Creditcardclient Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCreditcardclientID** | **number** | The unique ID of the Creditcardclient | [default to undefined]
**fkiCreditcarddetailID** | **number** | The unique ID of the Creditcarddetail | [default to undefined]
**bCreditcardclientrelationIsdefault** | **boolean** | Whether if it\&#39;s the creditcardclient is the default one | [default to undefined]
**sCreditcardclientDescription** | **string** | The description of the Creditcardclient | [default to undefined]
**bCreditcardclientAllowedcompanypayment** | **boolean** | Whether if it\&#39;s an allowedagencypayment | [default to undefined]
**bCreditcardclientAllowedtranquillit** | **boolean** | Whether if it\&#39;s an allowedtranquillit | [default to undefined]
**objCreditcarddetail** | [**CreditcarddetailResponseCompound**](CreditcarddetailResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { CreditcardclientResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CreditcardclientResponseCompound = {
    pkiCreditcardclientID,
    fkiCreditcarddetailID,
    bCreditcardclientrelationIsdefault,
    sCreditcardclientDescription,
    bCreditcardclientAllowedcompanypayment,
    bCreditcardclientAllowedtranquillit,
    objCreditcarddetail,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
