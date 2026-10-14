# ElectronicfundstransferListElement

A Electronicfundstransfer List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiElectronicfundstransferID** | **number** | The unique ID of the Electronicfundstransfer | [default to undefined]
**fkiPaymentmethodID** | **number** | The unique ID of the Paymentmethod | [default to undefined]
**fkiUserIDCreated** | **number** | The unique ID of the User | [optional] [default to undefined]
**sPaymentmethodDescriptionX** | **string** | The description of the Paymentmethod in the language of the requester | [optional] [default to undefined]
**sUserLoginnameCreated** | **string** | The login name of the User. | [optional] [default to undefined]
**iElectronicfundstransferNumber** | **number** | The number of the Electronicfundstransfer | [default to undefined]
**dtElectronicfundstransferDate** | **string** | The date of the Electronicfundstransfer | [default to undefined]
**iElectronicfundstransferTransactioncount** | **number** | The count of transactions in this Electronicfundstransfer. | [optional] [default to undefined]
**dElectronicfundstransferAmountvisible** | **string** | The sum of Electronicfundstransfertransaction we can consult. This sum can be different than total amount. | [optional] [default to undefined]

## Example

```typescript
import { ElectronicfundstransferListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ElectronicfundstransferListElement = {
    pkiElectronicfundstransferID,
    fkiPaymentmethodID,
    fkiUserIDCreated,
    sPaymentmethodDescriptionX,
    sUserLoginnameCreated,
    iElectronicfundstransferNumber,
    dtElectronicfundstransferDate,
    iElectronicfundstransferTransactioncount,
    dElectronicfundstransferAmountvisible,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
