# CreditcardmerchantResponseCompound

A Creditcardmerchant Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCreditcardmerchantID** | **number** | The unique ID of the Creditcardmerchant | [default to undefined]
**fkiBankaccountID** | **number** | The unique ID of the Bankaccount | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sLanguageNameX** | **string** | The Name of the Language in the language of the requester | [default to undefined]
**fkiCurrencyID** | **number** | The unique ID of the Currency. | [default to undefined]
**sCurrencyDescriptionX** | **string** | The description of the Currency in the language of the requester | [default to undefined]
**sBankaccountBankname** | **string** | The name of the bank | [optional] [default to undefined]
**bCreditcardmerchantDenyvisa** | **boolean** | Whether if visa are denied | [default to undefined]
**bCreditcardmerchantDenymastercard** | **boolean** | Whether if mastercard are denied | [default to undefined]
**bCreditcardmerchantDenyamex** | **boolean** | Whether if amex are denied | [default to undefined]
**bCreditcardmerchantIsactive** | **boolean** | Whether the creditcardmerchant is active or not | [default to undefined]
**sCreditcardmerchantDescription** | **string** | The description of the Creditcardmerchant | [default to undefined]
**sCreditcardmerchantStoreid** | **string** | The storeid of the Creditcardmerchant | [default to undefined]

## Example

```typescript
import { CreditcardmerchantResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CreditcardmerchantResponseCompound = {
    pkiCreditcardmerchantID,
    fkiBankaccountID,
    fkiLanguageID,
    sLanguageNameX,
    fkiCurrencyID,
    sCurrencyDescriptionX,
    sBankaccountBankname,
    bCreditcardmerchantDenyvisa,
    bCreditcardmerchantDenymastercard,
    bCreditcardmerchantDenyamex,
    bCreditcardmerchantIsactive,
    sCreditcardmerchantDescription,
    sCreditcardmerchantStoreid,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
