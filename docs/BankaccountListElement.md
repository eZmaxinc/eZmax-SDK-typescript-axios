# BankaccountListElement

A Bankaccount List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiBankaccountID** | **number** | The unique ID of the Bankaccount | [default to undefined]
**sBankaccountBankname** | **string** | The name of the bank | [default to undefined]
**sBankaccountTransit** | **string** | The transit of the Bankaccount | [default to undefined]
**sBankaccountInstitution** | **string** | The institution of the Bankaccount | [default to undefined]
**sBankaccountAccount** | **string** | The account of the Bankaccount | [default to undefined]
**sBankaccountNumber** | **string** | The account number of the Bankaccount | [default to undefined]
**eBankaccountType** | [**FieldEBankaccountType**](FieldEBankaccountType.md) |  | [optional] [default to undefined]
**bBankaccountCommissionprocessing** | **boolean** | Whether if it\&#39;s an commissionprocessing | [optional] [default to undefined]
**bBankaccountIsactive** | **boolean** | Whether the Bankaccount is active or not | [default to undefined]
**iGlaccountCode** | **number** | The Code of the Glaccount | [default to undefined]
**sGlaccountDescriptionX** | **string** | The Description for the Glaccount in the language of the requester | [default to undefined]

## Example

```typescript
import { BankaccountListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BankaccountListElement = {
    pkiBankaccountID,
    sBankaccountBankname,
    sBankaccountTransit,
    sBankaccountInstitution,
    sBankaccountAccount,
    sBankaccountNumber,
    eBankaccountType,
    bBankaccountCommissionprocessing,
    bBankaccountIsactive,
    iGlaccountCode,
    sGlaccountDescriptionX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
