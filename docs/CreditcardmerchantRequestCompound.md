# CreditcardmerchantRequestCompound

A Creditcardmerchant Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCreditcardmerchantID** | **number** | The unique ID of the Creditcardmerchant | [optional] [default to undefined]
**fkiBankaccountID** | **number** | The unique ID of the Bankaccount | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**fkiCurrencyID** | **number** | The unique ID of the Currency. | [default to undefined]
**bCreditcardmerchantDenyvisa** | **boolean** | Whether if visa are denied | [default to undefined]
**bCreditcardmerchantDenymastercard** | **boolean** | Whether if mastercard are denied | [default to undefined]
**bCreditcardmerchantDenyamex** | **boolean** | Whether if amex are denied | [default to undefined]
**bCreditcardmerchantIsactive** | **boolean** | Whether the creditcardmerchant is active or not | [default to undefined]
**sCreditcardmerchantApitoken** | **string** | The apitoken of the Creditcardmerchant | [optional] [default to undefined]
**sCreditcardmerchantDescription** | **string** | The description of the Creditcardmerchant | [default to undefined]
**sCreditcardmerchantStoreid** | **string** | The storeid of the Creditcardmerchant | [default to undefined]

## Example

```typescript
import { CreditcardmerchantRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CreditcardmerchantRequestCompound = {
    pkiCreditcardmerchantID,
    fkiBankaccountID,
    fkiLanguageID,
    fkiCurrencyID,
    bCreditcardmerchantDenyvisa,
    bCreditcardmerchantDenymastercard,
    bCreditcardmerchantDenyamex,
    bCreditcardmerchantIsactive,
    sCreditcardmerchantApitoken,
    sCreditcardmerchantDescription,
    sCreditcardmerchantStoreid,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
