# DeposittransitchequeListElement

A Deposittransitcheque List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDeposittransitchequeID** | **number** | The unique ID of the Deposittransitcheque | [default to undefined]
**fkiBankaccountID** | **number** | The unique ID of the Bankaccount | [default to undefined]
**fkiDepositID** | **number** | The unique ID of the Deposit | [optional] [default to undefined]
**sDeposittransitchequeNumber** | **string** | The number of the Deposittransitcheque | [default to undefined]
**dtDeposittransitchequeDate** | **string** | The date of the Deposittransitcheque | [default to undefined]
**dDeposittransitchequeAmount** | **string** | The amount of the Deposittransitcheque | [default to undefined]
**sBankaccountBankname** | **string** | The name of the bank | [default to undefined]
**sPeriodYYYYMM** | **string** | The YYYYMM of the Period | [default to undefined]
**sCustomerName** | **string** | The name of the Customer | [default to undefined]

## Example

```typescript
import { DeposittransitchequeListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DeposittransitchequeListElement = {
    pkiDeposittransitchequeID,
    fkiBankaccountID,
    fkiDepositID,
    sDeposittransitchequeNumber,
    dtDeposittransitchequeDate,
    dDeposittransitchequeAmount,
    sBankaccountBankname,
    sPeriodYYYYMM,
    sCustomerName,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
