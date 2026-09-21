# DepositListElement

A Deposit List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDepositID** | **number** | The unique ID of the Deposit | [default to undefined]
**fkiBankaccountID** | **number** | The unique ID of the Bankaccount | [default to undefined]
**fkiPeriodID** | **number** | The unique ID of the Period | [default to undefined]
**fkiUserIDCreated** | **number** | The unique ID of the User | [default to undefined]
**sDepositNumber** | **string** | The number of the Deposit | [default to undefined]
**dtDepositDate** | **string** | The date of the Deposit | [default to undefined]
**dDepositTotal** | **string** | The total of the Deposit | [default to undefined]
**dtCreatedDate** | **string** | The date and time at which the object was created | [default to undefined]
**bDepositDraft** | **boolean** | Whether if it\&#39;s an draft | [default to undefined]
**bDepositReconciled** | **boolean** | Whether if it\&#39;s reconciled | [default to undefined]
**fkiReconciliationID** | **number** | The unique ID of the Reconciliation | [optional] [default to undefined]
**sBankaccountBankname** | **string** | The name of the bank | [default to undefined]
**sPeriodYYYYMM** | **string** | The YYYYMM of the Period | [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [default to undefined]

## Example

```typescript
import { DepositListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DepositListElement = {
    pkiDepositID,
    fkiBankaccountID,
    fkiPeriodID,
    fkiUserIDCreated,
    sDepositNumber,
    dtDepositDate,
    dDepositTotal,
    dtCreatedDate,
    bDepositDraft,
    bDepositReconciled,
    fkiReconciliationID,
    sBankaccountBankname,
    sPeriodYYYYMM,
    sUserLoginname,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
