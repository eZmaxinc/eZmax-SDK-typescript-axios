# CreditcardclientListElement

A Creditcardclient List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCreditcardclientID** | **number** | The unique ID of the Creditcardclient | [default to undefined]
**fkiCreditcarddetailID** | **number** | The unique ID of the Creditcarddetail | [default to undefined]
**fkiCreditcardtypeID** | **number** | The unique ID of the Creditcardtype | [default to undefined]
**bCreditcardclientrelationIsdefault** | **boolean** | Whether if it\&#39;s the creditcardclient is the default one | [default to undefined]
**sCreditcardclientDescription** | **string** | The description of the Creditcardclient | [default to undefined]
**bCreditcardclientAllowedcompanypayment** | **boolean** | Whether if it\&#39;s an allowedagencypayment | [default to undefined]
**bCreditcardclientAllowedtranquillit** | **boolean** | Whether if it\&#39;s an allowedtranquillit | [default to undefined]
**iCreditcarddetailExpirationmonth** | **number** | The expirationmonth of the Creditcarddetail | [default to undefined]
**iCreditcarddetailExpirationyear** | **number** | The expirationyear of the Creditcarddetail | [default to undefined]
**iCreditcarddetailLastdigits** | **number** | The last digits of the Creditcarddetail | [default to undefined]

## Example

```typescript
import { CreditcardclientListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CreditcardclientListElement = {
    pkiCreditcardclientID,
    fkiCreditcarddetailID,
    fkiCreditcardtypeID,
    bCreditcardclientrelationIsdefault,
    sCreditcardclientDescription,
    bCreditcardclientAllowedcompanypayment,
    bCreditcardclientAllowedtranquillit,
    iCreditcarddetailExpirationmonth,
    iCreditcarddetailExpirationyear,
    iCreditcarddetailLastdigits,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
